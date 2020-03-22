#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <elf.h>

#define MIN_ELF_SIZE (16)

typedef struct {
	const char* path;
	void* addr;
	size_t size;
} MappedFile;

const char* str_e_type(Elf64_Half e_type);
const char* str_e_machine(Elf64_Half e_machine);

bool init_mapped_file(MappedFile* out, const char* path, int open_flags, mode_t open_mode, int mmap_prot, int mmap_flags);
bool check_elf_sanity(MappedFile* elf, Elf64_Half expected_type);

int main(int argc, char** argv) 
{
	if (argc != 4) {	
		fprintf(stderr, "usage: %s <ET_EXEC> <ET_REL> <target ET_EXEC>\n", argv[0]);
		return 1;
	}
	MappedFile exec, rel;
	if (!init_mapped_file(&exec, argv[1], O_RDONLY, 0, PROT_READ, MAP_PRIVATE)
	||  !init_mapped_file(&rel, argv[2], O_RDONLY, 0, PROT_READ, MAP_PRIVATE)) {
		return 1;
	}

	if(!check_elf_sanity(&exec, ET_EXEC)
	|| !check_elf_sanity(&rel, ET_REL)) {
		return 1;
	}

	printf("Done\n");
	return 0;
}

bool init_mapped_file(MappedFile* out, const char* path, int open_flags, mode_t open_mode, int mmap_prot, int mmap_flags)
{
	bool status = false;
	out->path = path;
	
	int fd = open(path, open_flags, open_mode);
	if (-1 == fd) {
		fprintf(stderr, "%s: failed to open: %s\n", path, strerror(errno));
		goto clean_open;
	}

	struct stat statbuf;
	if (-1 == fstat(fd, &statbuf)) {
		fprintf(stderr, "%s: failed to get size: %s\n", path, strerror(errno));
		goto clean_open;
	}
	out->size = statbuf.st_size;

	out->addr = mmap(NULL, out->size, mmap_prot, mmap_flags, fd, 0);
	if (MAP_FAILED == out->addr) {
		fprintf(stderr, "%s: failed to mmap: %s\n", path, strerror(errno));
		goto clean_mmap;
	}

	// TLDR: It's ok to close mmapped file.
	// POSIX_MANUAL:
	// The mmap() function adds an extra reference to the file associated with
	// the file descriptor fd which is not removed by a subsequent close()
	// on that file descriptor. This reference is removed when there are no 
	// more mappings to the file. 
	status = true;
	goto clean_open;

clean_mmap:
	if (out->addr != NULL && out->addr != MAP_FAILED) {
		munmap(out->addr, out->size);
	}
clean_open:
	if (fd > 0) {
		close(fd);
	}
	return status;
}

bool check_elf_sanity(MappedFile* elf, Elf64_Half expected_type)
{
	// size
	if (elf->size < MIN_ELF_SIZE) {
		fprintf(stderr, "%s: file is too short (%d < %d) to be parsed as ELF\n", elf->path, (int) elf->size, MIN_ELF_SIZE);
		return false;
	}

	// ident
	const char* magic = (const char*) (elf->addr) + EI_MAG0;
	uint8_t* ident = (uint8_t*) elf->addr;
	bool magic_ok = (0 == strncmp(magic, ELFMAG, SELFMAG));
	bool class_ok = ident[EI_CLASS] == ELFCLASS64;
	bool data_ok  = ident[EI_DATA] == ELFDATA2LSB;
	bool ident_ok = magic_ok && class_ok && data_ok;
	if (!ident_ok) {
		fprintf(stderr, "%s: invalid magic/class/data\n", elf->path);
		return false;
	}

	// header
	Elf64_Ehdr* hdr = (Elf64_Ehdr*) elf->addr;
	
	// type: rel/exec
	if (hdr->e_type != expected_type) {
		fprintf(stderr, "%s: expected elf type %s, found %s\n", elf->path, str_e_type(expected_type), str_e_type(hdr->e_type));
		return false;
	}

	// machine: x86_64
	const Elf64_Half expected_machine = EM_X86_64;
	if (hdr->e_machine != expected_machine) {
		fprintf(stderr, "%s: expected elf machine %s, found %s: \n", elf->path, str_e_machine(expected_machine), str_e_machine(hdr->e_machine));
		return false;
	}

	return true;
}

const char* str_e_type(Elf64_Half e_type)
{
	switch (e_type) {
		case ET_REL: return "rel";
		case ET_EXEC: return "exec";
		default: return "(unknown)";
	}
}

const char* str_e_machine(Elf64_Half e_machine)
{
	switch (e_machine) {
		case EM_X86_64: return "x86_64";
		default: return "(unknown)";
	}
}
