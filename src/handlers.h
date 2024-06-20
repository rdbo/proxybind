#ifndef HANDLERS_H
#define HANDLERS_H

#include <unistd.h>

void
pre_sys_socket(pid_t pid);

void
post_sys_socket(pid_t pid);

#endif
