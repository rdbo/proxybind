#include "handlers.hpp"
#include "utils.hpp"
#include <sys/ptrace.h>
#include <unordered_map>

/// Cached information about the socket file descriptors.
/// Can be retrieved and modified on a per-request basis, depending on the syscall
static std::unordered_map<int, proxybind_sockinfo_t> sockinfo_list;

void
pre_sys_socket(pid_t pid, struct user_regs_struct *regs)
{
	return;
}

void
post_sys_socket(pid_t pid, struct user_regs_struct *regs)
{
	int sockfd;
	proxybind_sockinfo_t sockinfo;

	sockfd = (int)regs->rax;
	if (sockfd == -1)
		return;
	
	sockinfo.sockfd = sockfd;
	sockinfo.socktype = regs->rsi ; /* NOTE: All registers except rcx, r11, rax are preserved during the syscall, so this is reliable */
	sockinfo.pid = pid;
	sockinfo.creation_time = clock();
	sockinfo.sockaddr = { 0 };
	sockinfo.sockaddr_len = 0;

	sockinfo_list.insert_or_assign(sockfd, sockinfo);
	log("[proxybind] created socket sockinfo (sockfd: %d, socktype: %d, pid: %d, creation_time: %ld) after successfull SYS_socket\n",
	    sockfd, sockinfo.socktype, sockinfo.pid, sockinfo.creation_time);

	return;
}

void
pre_sys_connect(pid_t pid, struct user_regs_struct *regs)
{
	return;
}

void
post_sys_connect(pid_t pid, struct user_regs_struct *regs)
{
	int sockfd;
	long sockaddr_ptr;
	socklen_t sockaddr_len;
	struct sockaddr sockaddr;
	int result;

	result = (int)regs->rax;
	if (result)
		return;

	sockfd = (int)regs->rdi;
	sockaddr_ptr = regs->rsi;
	sockaddr_len = (socklen_t)regs->rdx;

	if (ptrace_read(pid, sockaddr_ptr, &sockaddr, sizeof(sockaddr)) == -1) {
		log("[proxybind] error: failed to read sockaddr on SYS_connect");
		perror("");
		return;
	}

	sockinfo_list[sockfd].sockaddr = sockaddr;
	sockinfo_list[sockfd].sockaddr_len = sockaddr_len;

	log("[proxybind] bound new sockaddr for socket '%d' after successful SYS_connect (family: %d, len: %d)\n", sockfd, sockaddr.sa_family, sockaddr_len);
}

void
pre_sys_sendto(pid_t pid, struct user_regs_struct *regs)
{
	int sockfd;
	long buf;
	size_t len;
	int flags;
	long sockaddr_ptr;
	struct sockaddr sockaddr;
	size_t sockaddr_len;
	proxybind_header_t header;
	
	sockfd = (int)regs->rdi;
	buf = regs->rsi;
	len = (size_t)regs->rdx;
	flags = (int)regs->r10;
	sockaddr_ptr = regs->r8;
	sockaddr_len = regs->r9;

	if (ptrace_read(pid, sockaddr_ptr, &sockaddr, sizeof(sockaddr)) == -1) {
		log("[proxybind] error: failed to read sockaddr on SYS_sendto");
		perror("");
		return;
	}

	if (sockinfo_list.find(sockfd) == sockinfo_list.end()) {
		log("[proxybind] error: sockfd '%d' is not present in the sockinfo_list (SYS_sendto)\n", sockfd);
		return;
	}

	header.sockinfo = sockinfo_list[sockfd];
	header.payload_size = buf;

	log("[proxybind] intercepted 'SYS_sendto' for sockfd '%d' with message length '%lu'\n", sockfd, len);
}

void
post_sys_sendto(pid_t pid, struct user_regs_struct *regs)
{
	
}
