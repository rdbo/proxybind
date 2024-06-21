#ifndef HANDLERS_H
#define HANDLERS_H

#include <unistd.h>
#include <sys/socket.h>
#include <sys/user.h>
#include <time.h>

typedef struct proxybind_header_t {
	int sockfd;
	pid_t pid;
	clock_t creation_time;
	struct sockaddr sockaddr;
	size_t payload_size;
} proxybind_header_t;

void
pre_sys_socket(pid_t pid, struct user_regs_struct *regs);

void
post_sys_socket(pid_t pid, struct user_regs_struct *regs);

#endif
