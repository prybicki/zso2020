#include "common.h"

void do_write(int fd, char *buf, int size, int pos) {
	struct iovec iov[2];
	iov[0].iov_base = buf;
	iov[0].iov_len = size / 3;
	iov[1].iov_base = &buf[size / 3];
	iov[1].iov_len = size - size / 3;

	if (lseek(fd, pos, SEEK_SET) != pos)
		syserr("lseek");

	if (writev(fd, iov, 2) != size)
		syserr("writev");
}
	
void do_read(int fd, char *buf, int size, int pos) {
	struct iovec iov[2];
	if (lseek(fd, pos, SEEK_SET) != pos)
		syserr("lseek");

	iov[0].iov_base = buf;
	iov[0].iov_len = size / 2;
	iov[1].iov_base = &buf[size / 2];
	iov[1].iov_len = size - size / 2;

	if (readv(fd, iov, 2) < 0)
		syserr("invalid readv");
}

