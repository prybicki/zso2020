#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#define BUFFER_LENGTH 1024
int main(int argc, char** argv)
{
	if (argc != 2) {
		printf("bad args\n");
	}

	int fd = open(argv[1], O_RDWR | 040000000);
	perror("open");

	char cmd;
	off_t number = 2;
	char buffer[BUFFER_LENGTH];
	struct stat statbuf;
	while (1) {
		scanf("%c", &cmd);
		switch (cmd) {
		case 'l':
			scanf("%ld", &number);
			if (number >= 0) {
				lseek(fd, number, SEEK_SET);
			}
			else {
				lseek(fd, 0, SEEK_END);
			}
			perror("lseek");
			break;
		case 'w':
			scanf("%s", buffer);
			write(fd, buffer, strlen(buffer));
			perror("write");
			break;
		case 'r':
			scanf("%ld", &number);
			ssize_t rd = read(fd, buffer, number);
			buffer[rd] = 0;
			perror("read");
			printf("'%s' [%zd]\n", buffer, rd);
			break;
		case 't':
			scanf("%ld", &number);
			ftruncate(fd, number);
			perror("ftruncate");
			break;
		case 's':
			fstat(fd, &statbuf);
			perror("fstat");
			printf("fstat=%lld\n", statbuf.st_size);
			break;
		case 'f':
			fsync(fd);
			perror("fsync");
			break;
		default:
			break;
		}
	}
}
