#include "utils.h"
#include <sys/ptrace.h>
#include <memory.h>
#include <errno.h>
#include <stdio.h>

void
die(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

size_t
ptrace_read(pid_t pid, long addr, void *buf, size_t size)
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

		memcpy(&databuf[bytes_read], &data, read_diff);
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
