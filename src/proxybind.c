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

typedef uintmax_t reg_t;

void
syscall_listener(pid_t pid)
{
	int status;
	reg_t reg, stack;
	int syscall_num;
	struct sockaddr sockaddr;
	struct sockaddr_in *sockaddr_in;
	char ipv4[INET_ADDRSTRLEN];
	int sockfd;
	struct sockaddr orig_sockaddrs[256] = { 0 };
	unsigned char *buf;
	size_t bufsize;
	size_t size;
	struct user_regs_struct regs;

	for (;;) {
		ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
		waitpid(pid, &status, 0);
		if (WIFEXITED(status))
			break;
		
		reg = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * ORIG_RAX, NULL);
		syscall_num = (int)reg;
		log("[*] caught syscall: %d\n", syscall_num);

		ptrace(PTRACE_GETREGS, pid, NULL, &regs);

		/* Pre-syscall handlers */
		switch (syscall_num) {
		case SYS_socket:
			pre_sys_socket(pid, (int)regs.rsi, (int)regs.rdi, (int)regs.rdx);
			break;
		}

		/* Run syscall */
		ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
		waitpid(pid, &status, 0);
		if (WIFEXITED(status))
			break;

		reg = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * RAX, NULL);
		log("[*] syscall ret: %zu\n", reg);

		/* Post-syscall handlers */
		switch (syscall_num) {
		case SYS_socket:
			post_sys_socket(pid, (int)reg);
			break;
		}
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
