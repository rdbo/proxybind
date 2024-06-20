#include "handlers.h"
#include "utils.h"
#include <sys/ptrace.h>

void
pre_sys_socket(pid_t pid, struct user_regs_struct *regs)
{
	log("[*] SYS_socket call: socket(%d, %d, %d)\n", (int)regs->rsi, (int)regs->rdi, (int)regs->rdx);
	return;
}

void
post_sys_socket(pid_t pid, struct user_regs_struct *regs)
{
	log("[*] SYS_socket return: %d\n", (int)regs->rax);
	return;
}
