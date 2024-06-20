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
#include "utils.h"
#include "handlers.h"

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
		if (WIFEXITED(status))
			break;

		ptrace(PTRACE_GETREGS, pid, NULL, &regs);
		syscall_num = (int)regs.rax;
		log("[*] caught syscall: %d\n", syscall_num);

		/* Pre-syscall handlers */
		switch (syscall_num) {
		case SYS_socket:
			pre_sys_socket(pid, &regs);
			break;
		}

		/* Update regs after pre-syscall handlers */
		ptrace(PTRACE_SETREGS, pid, NULL, &regs);

		/* Run syscall */
		ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
		waitpid(pid, &status, 0);
		if (WIFEXITED(status))
			break;

		ptrace(PTRACE_GETREGS, pid, NULL, &regs);
		log("[*] syscall ret: %ld\n", regs.rax);

		/* Post-syscall handlers */
		switch (syscall_num) {
		case SYS_socket:
			post_sys_socket(pid, &regs);
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

	pid = fork();
	if (pid == 0) {
		char **program_argv = NULL;

		log("waiting for tracer...\n");
		ptrace(PT_TRACE_ME, 0, NULL, NULL);
		raise(SIGSTOP);

		if (argc > 2) {
			program_argv = &argv[2];
		}

		execve(argv[1], program_argv, NULL);
	} else {
		waitpid(pid, NULL, 0);
		log("tracer attached\n");

		syscall_listener(pid);
	}

	return 0;
}
