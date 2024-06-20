#include "handlers.h"
#include "utils.h"
#include <sys/ptrace.h>
#include <sys/reg.h>

void
pre_sys_socket(pid_t pid, int domain, int type, int protocol)
{
	log("[*] SYS_socket call: socket(%d, %d, %d)\n", domain, type, protocol);
	return;
}

void
post_sys_socket(pid_t pid, int sockfd)
{
	log("[*] SYS_socket return: %d\n", sockfd);
	return;
}
