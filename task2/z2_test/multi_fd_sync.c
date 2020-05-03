#include "common.h"

const char msg[] = "Lorem ipsum dolor sit amet\n";
const int part_len = 5;

int main() {
	int fd, fd2;

	if (!(fd = open("tst", O_RDWR | O_BUFFERED_WRITE)))
		syserr("Unable to open");

	if (!(fd2 = open("tst", O_RDWR | O_BUFFERED_WRITE)))
		syserr("Unable to open");

	if (write(fd, msg, part_len) != part_len)
		syserr("Write error");

	if (lseek(fd2, part_len, SEEK_SET) != part_len)
		syserr("lseek");

	if (write(fd2, &msg[part_len], strlen(msg) - part_len) < 0)
		syserr("write fd2");

	fsync(fd);
	fsync(fd2);

	close(fd);
	close(fd2);
	return 0;
}


