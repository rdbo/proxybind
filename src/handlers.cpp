#include "handlers.hpp"
#include "utils.hpp"
#include <sys/ptrace.h>
#include <unordered_map>

static std::unordered_map<int, proxybind_header_t> socket_headers;

void
pre_sys_socket(pid_t pid, struct user_regs_struct *regs)
{
	return;
}

void
post_sys_socket(pid_t pid, struct user_regs_struct *regs)
{
	int sockfd;
	proxybind_header_t header;

	sockfd = (int)regs->rax;
	if (sockfd == -1)
		return;
	
	header.sockfd = sockfd;
	header.socktype = regs->rsi ; /* NOTE: All registers except rcx, r11, rax are preserved during the syscall, so this is reliable */
	header.pid = pid;
	header.creation_time = clock();
	header.sockaddr = { 0 };
	header.payload_size = 0;

	socket_headers.insert_or_assign(sockfd, header);
	log("[proxybind] created socket header (sockfd: %d, socktype: %d, pid: %d, creation_time: %ld) after successfull SYS_socket\n",
	    sockfd, header.socktype, header.pid, header.creation_time);

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
	struct sockaddr sockaddr;
	int result;

	result = (int)regs->rax;
	if (result)
		return;

	sockfd = (int)regs->rdi;
	sockaddr_ptr = regs->rsi;

	if (ptrace_read(pid, sockaddr_ptr, &sockaddr, sizeof(sockaddr)) == -1) {
		log("[proxybind] error: failed to read sockaddr on SYS_connect");
		perror("");
		return;
	}

	socket_headers[sockfd].sockaddr = sockaddr;

	log("[proxybind] bound new sockaddr for socket '%d' with family '%d' after successful SYS_connect\n", sockfd, sockaddr.sa_family);
}
