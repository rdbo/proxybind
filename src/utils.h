#ifndef UTILS_H
#define UTILS_H

#include <stdlib.h>
#include <unistd.h>

void die(const char *msg);

size_t
ptrace_read(pid_t pid, long addr, void *buf, size_t size);

size_t
ptrace_write(pid_t pid, long addr, void *src, size_t size);

#endif
