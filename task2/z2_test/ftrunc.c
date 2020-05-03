#include "common.h"

const char msg[] = "Lorem ipsum dolor sit amet\n";
const char orig[] = "DEADBEEF\n";
const int trunc_len = 5;

int main() {
	int fd, res;
	char buf[128];

	if(!(fd = open("tst", O_RDWR | O_BUFFERED_WRITE)))
		syserr("Unable to open");

	// Truncate existing content
	if (ftruncate(fd, trunc_len) < 0)
		syserr("truncate");

	if (lseek(fd, 0, SEEK_SET) != 0)
		syserr("lseek");

	if ((res = read(fd, buf, sizeof(buf))) != trunc_len)
		perr("Invalid read");

	if (memcmp(buf, orig, trunc_len) != 0)
		perr("Invalid data");

	// Write new data and truncate
	if (lseek(fd, 0, SEEK_SET) != 0)
		syserr("lseek");

	if (write(fd, msg, sizeof(msg)) != sizeof(msg))
		syserr("Write error");

	if (ftruncate(fd, trunc_len) < 0)
		syserr("truncate");

	if (lseek(fd, 0, SEEK_SET) != 0)
		syserr("lseek");

	if ((res = read(fd, buf, sizeof(buf))) != trunc_len)
	{
		fprintf(stderr, "%d\n", res);
		syserr("read");
	}

	if (memcmp(msg, buf, trunc_len) != 0)
		perr("Read invalid data");

	close(fd);
	return 0;
}


