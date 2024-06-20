#include <netinet/in.h>
#include <unistd.h>
#include <signal.h>
#include <syscall.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

typedef uintmax_t reg_t;

void die(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

size_t
ptrace_read(pid_t pid, void *buf, long addr, size_t size)
{
	char *databuf = (char *)buf;
	size_t bytes_read;
	long data;
	const size_t data_size = sizeof(data);
	size_t read_diff;
	size_t diff;

	for (bytes_read = 0; bytes_read < size; bytes_read += read_diff) {
		diff = size - bytes_read;

		errno = 0;
		data = ptrace(PTRACE_PEEKDATA, pid, addr + bytes_read, NULL);
		if (data == -1 && errno)
			break;
		
		if (diff >= data_size) {
			read_diff = data_size;
		} else {
			read_diff = diff;
		}

		memcpy(&databuf[bytes_read], &data, data_size);
	}

	return bytes_read;
}

size_t
ptrace_write(pid_t pid, long addr, void *src, size_t size)
{
	char *databuf = (char *)src;
	size_t bytes_written;
	long data;
	const size_t data_size = sizeof(data);
	size_t write_diff;
	size_t diff;
	long destaddr;

	for (bytes_written = 0; bytes_written < size; bytes_written += write_diff) {
		diff = size - bytes_written;
		destaddr = addr + bytes_written;
		if (diff >= data_size) {
			write_diff = data_size;
		} else {
			/* Read missing aligned bytes for a ptrace write into the 
			 * data before writing */
			errno = 0;
			data = ptrace(PTRACE_PEEKDATA, pid, destaddr, NULL);
			if (data == -1 && errno)
				break;

			write_diff = diff;
		}
		memcpy(&data, &databuf[bytes_written], write_diff);
		
		if (ptrace(PTRACE_POKEDATA, pid, destaddr, data))
			break;
	}

	return bytes_written;
}

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

	for (;;) {
		ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
		waitpid(pid, &status, 0);
		if (WIFEXITED(status))
			break;
		
		reg = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * ORIG_RAX, NULL);
		syscall_num = (int)reg;
		printf("[*] caught syscall: %d\n", syscall_num);

		if (reg == SYS_connect) {
			reg = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * RDI, NULL);
			sockfd = (int)reg;
			printf("[*] tracee attempted to connect (sockfd: %d)\n", sockfd);

			reg = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * RDX, NULL);
			printf("[*] sockaddr len: %zu\n", reg);

			reg = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * RSI, NULL);
			printf("[*] sockaddr pointer: %zx\n", reg);

			if (ptrace_read(pid, (void *)&sockaddr, (long)reg, sizeof(sockaddr)) != sizeof(sockaddr)) {
				perror("[!] failed to read 'struct sockaddr' from tracee");
				continue;
			}

			/* Intercept only IPv4 connections */
			if (sockaddr.sa_family != AF_INET)
				continue;

			orig_sockaddrs[sockfd] = sockaddr;

			sockaddr_in = (struct sockaddr_in *)&sockaddr;

			printf("[*] sockaddr family: %hu\n", sockaddr_in->sin_family);

			inet_ntop(AF_INET, &sockaddr_in->sin_addr, ipv4, sizeof(ipv4));
			printf("[*] sockaddr ipv4: %s\n", ipv4);

			printf("[*] rerouting socket to proxy address...\n");
			sockaddr_in->sin_addr.s_addr = inet_addr("127.0.0.1");
			sockaddr_in->sin_port = htons(6969);
			if (ptrace_write(pid, (long)reg, (void *)&sockaddr, sizeof(sockaddr)) != sizeof(sockaddr)) {
				perror("[!] failed to reroute socket");
				continue;
			}
			printf("[*] socket rerouted successfully\n");
		} else if (reg == SYS_sendto) {
			reg = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * RDI, NULL);
			sockfd = (int)reg;
			printf("[*] tracee attempted to send data through socket (sockfd: %d)\n", sockfd);

			size = (size_t)ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * RDX);
			bufsize = sizeof(sockfd) + sizeof(struct sockaddr) + sizeof(size) + size; /* Reverse space for sockfd + original sockaddr + msg size + message buffer */
			buf = malloc(bufsize);

			/* Create new data */
			memcpy(buf, &sockfd, sizeof(sockfd));
			memcpy(&buf[sizeof(sockfd)], &orig_sockaddrs[sockfd], sizeof(struct sockaddr));
			memcpy(&buf[sizeof(sockfd) + sizeof(struct sockaddr)], &size, sizeof(size));
			/* Read message  */
			reg = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * RSI, NULL);
			ptrace_read(pid, &buf[sizeof(sockfd) + sizeof(struct sockaddr) + sizeof(size)], reg, size);

			/* Write new data payload on the stack (unmodified by system calls) */
			stack = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * RSP, NULL);
			reg = stack - bufsize;
			ptrace_write(pid, reg, buf, bufsize);

			/* Modify syscall parameter */
			ptrace(PTRACE_POKEUSER, pid, sizeof(long) * RSI, reg);
			ptrace(PTRACE_POKEUSER, pid, sizeof(long) * RDX, bufsize);
		}

		ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
		waitpid(pid, &status, 0);
		if (WIFEXITED(status))
			break;

		/*
		 * Spoof syscall return value - since we are modifying the write to the sockfd, we need
		 * to spoof the return value, which is the amount of bytes sent
		 */
		if (syscall_num == SYS_sendto) {
			reg = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * RAX, NULL);
			printf("[*] sendto return value: %zu (expected: %zu)\n", reg, bufsize);

			if (reg == bufsize) {
				reg = size;
			} else {
				reg = 0;
			}

			ptrace(PTRACE_POKEUSER, pid, sizeof(long) * RAX, reg);
		}
		
		reg = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * RAX, NULL);
		printf("[*] syscall ret: %zu\n", reg);
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

		printf("waiting for tracer...\n");
		ptrace(PT_TRACE_ME, 0, NULL, NULL);
		raise(SIGSTOP);

		if (argc > 2) {
			program_argv = &argv[2];
		}

		execve(argv[1], program_argv, NULL);
	} else {
		waitpid(pid, NULL, 0);
		printf("tracer attached\n");

		syscall_listener(pid);
	}

	return 0;
}
