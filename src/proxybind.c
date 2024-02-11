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
	reg_t reg;
	struct sockaddr sockaddr;
	struct sockaddr_in *sockaddr_in;
	char ipv4[INET_ADDRSTRLEN];

	for (;;) {
		ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
		waitpid(pid, &status, 0);
		if (WIFEXITED(status))
			break;
		
		reg = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * ORIG_RAX, NULL);
		printf("[*] caught syscall: %zu\n", reg);

		if (reg == SYS_connect) {
			reg = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * RDI, NULL);
			printf("[*] tracee attempted to connect (sockfd: %d)\n", (int)reg);

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
		}

		ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
		waitpid(pid, &status, 0);
		if (WIFEXITED(status))
			break;
		
		reg = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * RAX, NULL);
		printf("[*] syscall ret: %zu\n", reg);
	}
}

void
dummy_client()
{
	int sockfd;
	struct sockaddr_in server;
	char buf[5] = { 0 };
	
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1) {
		die("failed to create socket");
	}

	printf("client socket fd: %d\n", sockfd);

	server.sin_addr.s_addr = inet_addr("127.0.0.1");
	server.sin_family = AF_INET;
	server.sin_port = htons(1337);

	if (connect(sockfd, (struct sockaddr *)&server, sizeof(server))) {
		printf("client socket port after connect: %d\n", server.sin_port);
		die("failed to connect to server");
	}

	if (send(sockfd, "ping", 4, 0) == -1) {
		die("failed to send message to the server");
	}

	if (recv(sockfd, buf, sizeof(buf) - sizeof(buf[0]), 0) <= 0) {
		die("failed to receive message from the server");
	}
	printf("%s\n", buf);

	close(sockfd);
}

int
main()
{
	pid_t pid;
	printf("[proxybind]\n");

	pid = fork();
	if (pid == 0) {
		printf("waiting for tracer...\n");
		ptrace(PT_TRACE_ME, 0, NULL, NULL);
		raise(SIGSTOP);

		dummy_client();
	} else {
		waitpid(pid, NULL, 0);
		printf("tracer attached\n");

		syscall_listener(pid);
	}

	return 0;
}
