#ifndef __COMMON_H
#define __COMMON_H

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>   
#include <sys/types.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <string.h>

#define O_BUFFERED_WRITE 040000000

static inline void syserr(const char *c) {
	perror(c);
	exit(-1);
}

static inline void perr(const char *c) {
	fprintf(stderr, "%s\n", c);
	exit(-1);
}


void do_read(int fd, char *buf, int size, int pos);
void do_write(int fd, char *buf, int size, int pos);

#endif
