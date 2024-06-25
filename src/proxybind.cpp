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

void
syscall_listener()
{
	int status;
	int syscall_num;
	struct user_regs_struct regs;
	pid_t pid;

	for (;;) {
		pid = waitpid(-1, &status, 0);
		if (pid == -1) {
			log("[proxybind] no tracees left, stopping syscall listener...\n");
			break;
		}
		if (WIFEXITED(status)) {
			ptrace(PTRACE_DETACH, pid, NULL, SIGKILL);
			log("[proxybind] (tracee pid: %d) detached from process (reason: exited)\n", pid);
			continue;
		}

		ptrace(PTRACE_GETREGS, pid, NULL, &regs);
		syscall_num = (int)regs.orig_rax;
		log("[proxybind] (tracee pid: %d) caught syscall: %d\n", pid, syscall_num);

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

		/* Run syscall-exit */
		ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
		waitpid(pid, &status, 0);
		if (WIFEXITED(status)) {
			ptrace(PTRACE_DETACH, pid, NULL, SIGKILL);
			log("[proxybind] (tracee pid: %d) detached from process (reason: exited)\n", pid);
			continue;
		} else if (WIFSTOPPED(status)) {
			switch ((status >> 8) & 0xffff) {
			case (SIGTRAP | (PTRACE_EVENT_FORK << 8)):
			case (SIGTRAP | (PTRACE_EVENT_VFORK << 8)):
			case (SIGTRAP | (PTRACE_EVENT_CLONE << 8)):
				pid_t childpid;
				pid_t copy_pid = pid; // i do not know why this is needed, but after PTRACE_GETEVENTMSG, pid is being set to zero somehow? TODO: Fix this
				ptrace(PTRACE_GETEVENTMSG, pid, NULL, &childpid);
				pid = copy_pid;
				log("[proxybind] (tracee pid: %d) process forked (new child: %d)\n", pid, childpid);

				// The syscall didn't finish running yet, so we run 'PTRACE_SYSCALL' again to finish it
				ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
				waitpid(pid, NULL, 0);

				waitpid(childpid, NULL, 0); // Wait for child (should be on SIGSTOP state when created)
				ptrace(PTRACE_SYSCALL, childpid, NULL, NULL);

				break;
			}
		}

		ptrace(PTRACE_GETREGS, pid, NULL, &regs);
		log("[proxybind] (tracee pid: %d) syscall ret: %ld\n", pid, regs.rax);

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

		/* Step to next syscall-enter */
		ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
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

		/* Step to syscall */
		ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
		syscall_listener();
	}

	log("[proxybind] finished\n");

	return 0;
}
