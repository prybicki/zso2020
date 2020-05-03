#include "common.h"

const char msg[] = "Lorem ipsum dolor sit amet\n";

int main() {
	int fd;
	struct stat st;

	if(!(fd = open("tst", O_RDWR | O_BUFFERED_WRITE)))
		syserr("Unable to open");
	
	if (write(fd, msg, strlen(msg)) != strlen(msg))
        	syserr("Write error");

	if (fstat(fd, &st) != 0)
		syserr("fstat");

	if (st.st_size != strlen(msg))
		perr("Invalid size");

	close(fd);
	return 0;
}


