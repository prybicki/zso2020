#include "common.h"

const char msg[] = "Lorem ipsum dolor sit amet\n";
const char orig[] = "DEADBEEF\n";

int main() {
	int fd, fd2, res;
	char buf[128];

	memset(buf, 0, sizeof(buf));

	if (!(fd = open("tst", O_RDWR | O_BUFFERED_WRITE)))
		syserr("Unable to open");

	if (!(fd2 = open("tst", O_RDWR | O_BUFFERED_WRITE)))
		syserr("Unable to open");

	if (write(fd, msg, sizeof(msg)) != sizeof(msg))
		syserr("Write error");

	if ((res = read(fd2, buf, sizeof(buf))) < 0)
               syserr("read");

	if (res != strlen(orig) || memcmp(orig, buf, strlen(orig)) != 0)
		perr("Read invalid data");

	close(fd);
	close(fd2);
	return 0;
}


