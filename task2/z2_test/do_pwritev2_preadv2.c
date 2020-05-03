#define _GNU_SOURCE
#include "common.h"
#include <sys/uio.h>

void do_write(int fd, char *buf, int size, int pos) {
	struct iovec iov[2];
	iov[0].iov_base = buf;
	iov[0].iov_len = size / 3;
	iov[1].iov_base = &buf[size / 3];
	iov[1].iov_len = size - size / 3;

	if (pwritev2(fd, iov, 2, pos, 0) != size)
		syserr("writev");	
}

void do_read(int fd, char *buf, int size, int pos) {
	struct iovec iov[2];
	iov[0].iov_base = buf;
	iov[0].iov_len = size / 2;
	iov[1].iov_base = &buf[size / 2];
	iov[1].iov_len = size - size / 2;

	if (preadv2(fd, iov, 2, pos, 0) < 0)
		syserr("invalid readv");
}

