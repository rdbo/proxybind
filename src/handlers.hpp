#ifndef HANDLERS_H
#define HANDLERS_H

#include <unistd.h>
#include <sys/socket.h>
#include <sys/user.h>
#include <time.h>

typedef struct proxybind_sockinfo_t {
	int sockfd;
	int socktype;
	pid_t pid;
	clock_t creation_time;
	struct sockaddr sockaddr;
	socklen_t sockaddr_len;
} proxybind_sockinfo_t;

typedef struct proxybind_header_t {
	proxybind_sockinfo_t sockinfo;
	size_t payload_size;
} proxybind_header_t;

void
pre_sys_socket(pid_t pid, struct user_regs_struct *regs);

void
post_sys_socket(pid_t pid, struct user_regs_struct *regs);

void
pre_sys_connect(pid_t pid, struct user_regs_struct *regs);

void
post_sys_connect(pid_t pid, struct user_regs_struct *regs);

void
pre_sys_sendto(pid_t pid, struct user_regs_struct *regs);

void
post_sys_sendto(pid_t pid, struct user_regs_struct *regs);

#endif
