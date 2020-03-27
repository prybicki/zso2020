#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <elf.h>

// TODO: think it through
// Remove it or make it a real check (16 is arbitrary)
#define MIN_ELF_SIZE (16)

typedef struct {
	const char* path;
	void* addr;
	size_t size;
	
	Elf64_Ehdr* hdr;

	Elf64_Shdr* sct;
	size_t sct_count;

	Elf64_Phdr* prg;
	size_t prg_count;

	const char* strtab;
	size_t strtab_size;

	// Currently, an object file may have only one section of each type (SYMTAB, DYNSYM),
	// but this restriction may be relaxed in the future
	Elf64_Sym* sym;
	size_t sym_count;
} MappedELF;

const char* str_e_type(Elf64_Half e_type);
const char* str_e_machine(Elf64_Half e_machine);

bool mmap_path(const char* path, int open_flags, mode_t open_mode, int mmap_prot, int mmap_flags, void** out_addr, size_t* inout_size);
bool elf_check_sanity(MappedELF* elf, Elf64_Half expected_type);
const char* elf_section_name(MappedELF* elf, Elf64_Half idx)
{
	return elf->strtab + elf->sct[idx].sh_name;
}

typedef struct
{
	Elf64_Half sh_idx;
	Elf64_Xword sh_flags;
} SectionFlagsIdx;

int elf_section_flags_cmp(const void* void_lhs, const void* void_rhs)
{
	const SectionFlagsIdx* lhs = void_lhs;
	const SectionFlagsIdx* rhs = void_rhs;
	return (lhs->sh_flags < rhs->sh_flags) ? -1 : lhs->sh_flags > rhs->sh_flags;
}

bool elf_link(MappedELF* out, MappedELF* exec, MappedELF* rel)
{
	// Count SHF_ALLOC sections
	// readonly

	// Group sections by sorting by (flags & (SHF_WRITE | SHF_EXECINSTR))
	size_t alloc_sect_cnt = 0;
	SectionFlagsIdx* alloc_sect = malloc(rel->sct_count * sizeof(*alloc_sect));
	if (NULL == alloc_sect) {
		fprintf(stderr, "out of memory\n");
		return false;
	}
	for (size_t i = 0; i < rel->sct_count; ++i) {
		if (rel->sct[i].sh_flags & SHF_ALLOC) {
			alloc_sect[alloc_sect_cnt].sh_idx = i;
			alloc_sect[alloc_sect_cnt].sh_flags = (SHF_WRITE | SHF_EXECINSTR) & rel->sct[i].sh_flags;
			alloc_sect_cnt += 1;
		}
	}
	qsort(alloc_sect, alloc_sect_cnt, sizeof(*alloc_sect), elf_section_flags_cmp);
	
	for (size_t i = 0; i < alloc_sect_cnt; ++i) {
		printf("sect: %10s\t%ld\t%ld %ld %ld\n", elf_section_name(rel, alloc_sect[i].sh_idx),
		alloc_sect[i].sh_flags,
		alloc_sect[i].sh_flags & SHF_ALLOC,
		alloc_sect[i].sh_flags & SHF_WRITE,
		alloc_sect[i].sh_flags & SHF_EXECINSTR);
	}

	// Count new program headers
	size_t new_phdr_cnt = (alloc_sect_cnt > 0);
	for (size_t i = 1; i < alloc_sect_cnt; ++i) {
		if (alloc_sect[i].sh_flags != alloc_sect[i-1].sh_flags) {
			new_phdr_cnt += 1;
		}
	}
	printf("new headers: %zu\n", new_phdr_cnt);

	// write phdrs (old+new) to out file
	// remember to update virtual addresses where to load
	// write shdrs to out file
	// write sections (old+new)
	



	// size_t next = 0;
	// uint8_t* out_bytes = (uint8_t*) out->addr;

	
	// // Copy header
	// memcpy(out_bytes + next, exec->hdr, exec->hdr->e_ehsize);
	// next += exec->hdr->e_ehsize;
	// out->hdr = (Elf64_Ehdr*) out_bytes;


	// free(sections);

	return true;
}

int main(int argc, char** argv) 
{
	if (argc != 4) {	
		fprintf(stderr, "usage: %s <ET_EXEC> <ET_REL> <target ET_EXEC>\n", argv[0]);
		return 1;
	}
	MappedELF exec = {0};
	MappedELF rel = {0};
	MappedELF out = {0};

	exec.path = argv[1];
	rel.path = argv[2];
	out.path = argv[3];

	if (!mmap_path(exec.path, O_RDONLY, 0, PROT_READ, MAP_PRIVATE, &exec.addr, &exec.size)
	||  !mmap_path(rel.path, O_RDONLY, 0, PROT_READ, MAP_PRIVATE, &rel.addr, &rel.size)) {
		return 1;
	}

	if(!elf_check_sanity(&exec, ET_EXEC)
	|| !elf_check_sanity(&rel, ET_REL)) {
		return 1;
	}

	out.size = exec.size + rel.size;
	if (!mmap_path(out.path, 
	               O_RDWR | O_CREAT | O_TRUNC, 
	               S_IRUSR | S_IWUSR,
	               PROT_READ | PROT_WRITE, 
	               MAP_SHARED, 
	               &out.addr, &out.size)) {
		return 1;
	}

	if (!elf_link(&out, &exec, &rel)) {
		return 1;
	}

	return 0;
}

bool mmap_path(const char* path, int open_flags, mode_t open_mode, int mmap_prot, int mmap_flags, void** out_addr, size_t* inout_size)
{
	assert(out_addr != NULL);
	assert(inout_size != NULL);

	bool status = false;
	
	int fd = open(path, open_flags, open_mode);
	if (-1 == fd) {
		fprintf(stderr, "%s: failed to open: %s\n", path, strerror(errno));
		goto clean_nothing;
	}

	if (*inout_size == 0) {
		// get actual file size
		struct stat statbuf;
		if (-1 == fstat(fd, &statbuf)) {
			fprintf(stderr, "%s: failed to get size: %s\n", path, strerror(errno));
			goto clean_open;
		}
		*inout_size = statbuf.st_size;
	}
	else {
		// resize file
		if ((off_t) -1 == lseek(fd, *inout_size - 1, SEEK_SET)) {
			fprintf(stderr, "%s: failed to resize file (lseek): %s\n", path, strerror(errno));
			goto clean_open;
		}
		if (write(fd, "", 1) <= 0) {
			fprintf(stderr, "%s: failed to resize file (write): %s\n", path, strerror(errno));
			goto clean_open;
		}
	}

	void* mmap_addr = mmap(NULL, *inout_size, mmap_prot, mmap_flags, fd, 0);
	if (MAP_FAILED == mmap_addr) {
		fprintf(stderr, "%s: failed to mmap: %s\n", path, strerror(errno));
		goto clean_open;
	}
	*out_addr = mmap_addr;

	// TLDR: It's ok to close mmapped file.
	// POSIX_MANUAL:
	// The mmap() function adds an extra reference to the file associated with
	// the file descriptor fd which is not removed by a subsequent close()
	// on that file descriptor. This reference is removed when there are no 
	// more mappings to the file. 
	status = true;
	goto clean_open;

clean_open:
	if (fd > 0) {
		close(fd);
	}
clean_nothing:
	return status;
}

bool elf_check_sanity(MappedELF* elf, Elf64_Half expected_type)
{
	uint8_t* elf_bytes = (uint8_t*) elf->addr;
	// size
	if (elf->size < MIN_ELF_SIZE) {
		fprintf(stderr, "%s: file is too short (%d < %d) to be parsed as ELF\n", elf->path, (int) elf->size, MIN_ELF_SIZE);
		return false;
	}

	// ident
	bool magic_ok = elf_bytes[EI_MAG0] == ELFMAG0
	             && elf_bytes[EI_MAG1] == ELFMAG1
	             && elf_bytes[EI_MAG2] == ELFMAG2
	             && elf_bytes[EI_MAG3] == ELFMAG3;
	bool class_ok = elf_bytes[EI_CLASS] == ELFCLASS64;
	bool data_ok  = elf_bytes[EI_DATA] == ELFDATA2LSB;
	bool ident_ok = magic_ok && class_ok && data_ok;
	if (!ident_ok) {
		fprintf(stderr, "%s: invalid magic/class/data\n", elf->path);
		return false;
	}

	// header
	elf->hdr = (Elf64_Ehdr*) elf_bytes;
	
	// type: rel/exec
	if (elf->hdr->e_type != expected_type) {
		fprintf(stderr, "%s: expected elf type %s, found %s\n", elf->path, str_e_type(expected_type), str_e_type(elf->hdr->e_type));
		return false;
	}

	// machine: x86_64
	const Elf64_Half expected_machine = EM_X86_64;
	if (elf->hdr->e_machine != expected_machine) {
		fprintf(stderr, "%s: expected elf machine %s, found %s: \n", elf->path, str_e_machine(expected_machine), str_e_machine(elf->hdr->e_machine));
		return false;
	}

	// Section header table
	elf->sct = (Elf64_Shdr*) (elf_bytes + elf->hdr->e_shoff);
	if (elf->hdr->e_shoff < elf->hdr->e_ehsize) {
		elf->sct = NULL;
		// TODO: section header is needed always, because of syms, right?
		if (expected_type == ET_REL) {
			fprintf(stderr, "%s: no sections in ET_REL file\n", elf->path);
			return false;
		}
	}

	if (elf->sct != NULL && sizeof(Elf64_Shdr) != elf->hdr->e_shentsize) {
		fprintf(stderr, "%s: invalid section entry size (%zu != %zu)\n", elf->path, sizeof(Elf64_Shdr), (size_t) elf->hdr->e_shentsize);
		return false;
	}

	elf->sct_count = elf->hdr->e_shnum;
	if (elf->sct_count == SHN_UNDEF) {
		elf->sct_count = elf->sct[0].sh_size;
	}

	// Program header table
	elf->prg = (Elf64_Phdr*) (elf_bytes + elf->hdr->e_phoff);
	if (elf->hdr->e_phoff < elf->hdr->e_ehsize) {
		elf->prg = NULL;
		if (expected_type == ET_EXEC) {
			fprintf(stderr, "%s: no segments in ET_EXEC file\n", elf->path);
			return false;
		}
	}

	if (elf->prg != NULL && sizeof(Elf64_Phdr) != elf->hdr->e_phentsize) {
		fprintf(stderr, "%s: invalid segment entry size (%zu != %zu)\n",
		        elf->path, (size_t) elf->hdr->e_shentsize, sizeof(Elf64_Shdr));
		return false;
	}

	// String section
	elf->strtab = NULL;
	elf->strtab_size = 0;
	Elf64_Word str_idx = elf->hdr->e_shstrndx;
	if (str_idx != SHN_UNDEF) {
		if (elf->hdr->e_shstrndx == SHN_XINDEX) {
			str_idx = elf->sct[0].sh_link;
		}

		elf->strtab = (const char*) elf_bytes + elf->sct[str_idx].sh_offset;
		elf->strtab_size = elf->sct[str_idx].sh_size;
	}

	// Symbol section
	elf->sym = NULL;
	for (Elf64_Section i = 0; i < elf->hdr->e_shnum; ++i) {
		if (elf->sct[i].sh_type == SHT_SYMTAB) {
			if (elf->sct[i].sh_entsize != sizeof(Elf64_Sym)) {
				fprintf(stderr, "%s: invalid symtab entry size (%zu != %zu)\n",
				        elf->path, (size_t) elf->sct[i].sh_entsize, sizeof(Elf64_Sym));
				return false;
			}
			elf->sym = (Elf64_Sym*) elf_bytes + elf->sct[i].sh_offset;
			elf->sym_count = elf->sct[i].sh_size / elf->sct[i].sh_entsize;
			break;
		}
	}

	return true;
}

const char* str_e_type(Elf64_Half e_type)
{
	switch (e_type) {
		case ET_REL: return "rel";
		case ET_EXEC: return "exec";
		case ET_DYN: return "dyn";
		case ET_CORE: return "core";
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
