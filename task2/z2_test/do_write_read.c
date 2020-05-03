#include "common.h"

void do_read(int fd, char *buf, int size, int pos) {
	if (lseek(fd, pos, SEEK_SET) != pos)
		syserr("lseek");

	if (read(fd, buf, size) < 0)
		syserr("read fail");
}


void do_write(int fd, char *buf, int size, int pos) {
	if (lseek(fd, pos, SEEK_SET) != pos)
		syserr("lseek");

	if (write(fd, buf, size) != size)
		syserr("Write error");
}

