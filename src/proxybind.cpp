#include <netinet/in.h>
#include <unistd.h>
#include <signal.h>
#include <syscall.h>
#include <arpa/inet.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include "utils.hpp"
#include "handlers.hpp"
#include <thread>

void
syscall_listener(pid_t pid);

void
process_handler(pid_t childpid)
{
	log("[proxybind] started handler for child process '%d'\n", childpid);
	syscall_listener(childpid);
}

void
syscall_listener(pid_t pid)
{
	int status;
	int syscall_num;
	struct user_regs_struct regs;

	for (;;) {
		/* Step to syscall */
		ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
		waitpid(pid, &status, 0);
		if (WIFEXITED(status)) {
			ptrace(PTRACE_DETACH, pid, NULL, NULL);
			log("[proxybind] detached from process '%d' (reason: exited)\n", pid);
			break;
		}

		ptrace(PTRACE_GETREGS, pid, NULL, &regs);
		syscall_num = (int)regs.orig_rax;
		log("[proxybind] caught syscall: %d (process: %d)\n", syscall_num, pid);

		/* Pre-syscall handlers */
		switch (syscall_num) {
		case SYS_socket:
			pre_sys_socket(pid, &regs);
			break;
		case SYS_connect:
			pre_sys_connect(pid, &regs);
			break;
		case SYS_sendto:
			pre_sys_sendto(pid, &regs);
			break;
		}

		/* Update regs after pre-syscall handlers */
		ptrace(PTRACE_SETREGS, pid, NULL, &regs);

		/* Run syscall */
		ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
		waitpid(pid, &status, 0);
		if (WIFEXITED(status)) {
			ptrace(PTRACE_DETACH, pid, NULL, NULL);
			log("[proxybind] detached from process '%d' (reason: exited)\n", pid);
			break;
		} else if (WIFSTOPPED(status)) {
			switch (status >> 8) {
			case (SIGTRAP | (PTRACE_EVENT_FORK << 8)):
				pid_t childpid;
				ptrace(PTRACE_GETEVENTMSG, pid, NULL, &childpid);
				log("[proxybind] process '%d' forked (new child: %d)\n", pid, childpid);

				auto thread = std::thread(process_handler, childpid);
				thread.detach();
				break;
			}
		}

		ptrace(PTRACE_GETREGS, pid, NULL, &regs);
		log("[proxybind] syscall ret: %ld (process: %d)\n", regs.rax, pid);

		/* Post-syscall handlers */
		switch (syscall_num) {
		case SYS_socket:
			post_sys_socket(pid, &regs);
			break;
		case SYS_connect:
			post_sys_connect(pid, &regs);
			break;
		case SYS_sendto:
			post_sys_sendto(pid, &regs);
			break;
		}

		/* Update regs after post-syscall handlers */
		ptrace(PTRACE_SETREGS, pid, NULL, &regs);
	}
}

int
main(int argc, char **argv)
{
	pid_t pid;
	printf("[proxybind]\n");

	if (argc < 2) {
		printf("usage: proxybind <program>\n");
		return -1;
	}

	log("[proxybind] main pid: %d\n", getpid());

	pid = fork();
	if (pid == 0) {
		char **program_argv = NULL;

		log("[proxybind] waiting for tracer...\n");
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);

		if (argc > 2) {
			program_argv = &argv[2];
		}

		execvp(argv[1], program_argv);
	} else {
		int status;

		waitpid(pid, &status, 0);
		log("[proxybind] tracer attached to child pid: %d\n", pid);

		ptrace(PTRACE_SETOPTIONS, pid, NULL,
		       PTRACE_O_TRACEFORK | PTRACE_O_TRACEEXEC | PTRACE_O_TRACECLONE |
		       PTRACE_O_TRACESECCOMP | PTRACE_O_TRACEVFORK | PTRACE_O_EXITKILL);

		process_handler(pid);
	}

	return 0;
}
