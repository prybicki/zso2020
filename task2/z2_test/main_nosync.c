#include <sys/uio.h>
#include "common.h"

char msg[] = "Lorem ipsum dolor sit amet\n";
char buf[sizeof(msg)];

int main() {
	int fd;

	if(!(fd = open("tst", O_RDWR | O_BUFFERED_WRITE)))
		syserr("Unable to open");

	do_write(fd, msg, strlen(msg), 0);
	do_read(fd, buf, sizeof(msg), 0);
	if (memcmp(buf, msg, sizeof(msg)) != 0)
		perr("Invalid data");

	close(fd);

	return 0;
}


