#include "common.h"


void do_write(int fd, char *buf, int size, int pos) {
	if (pwrite(fd, buf, size, pos) != size)
		syserr("Write error");
}

void do_read(int fd, char *buf, int size, int pos) {
	if (pread(fd, buf, size, pos) < 0)
		syserr("read fail");
}
