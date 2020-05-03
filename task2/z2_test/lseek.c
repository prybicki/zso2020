#include "common.h"

const char msg[] = "Lorem ipsum dolor sit amet";

int main() {
	int fd;

	if(!(fd = open("tst", O_RDWR | O_BUFFERED_WRITE)))
		syserr("Unable to open");
	
	if (write(fd, msg, sizeof(msg)) != sizeof(msg))
	       	syserr("Write error");

	if (lseek(fd, 0, SEEK_END) != sizeof(msg))
		syserr("Invalid lseek result");

	close(fd);
	return 0;
}


