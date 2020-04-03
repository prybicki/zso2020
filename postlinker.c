#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

// TODO read docs on program loading
// TODO debug running it with glibc sources

#include <unistd.h>
#include <elf.h>

typedef struct {
	const char* path;
	void* addr;
	size_t size;
} MemFile;

// File accessors with safety features
char* at(MemFile* file, size_t offset, size_t elemsize);
char* at_arr(MemFile* file, size_t offset, size_t elemsize, size_t arr_sz, size_t idx);

// Checks if the field is within the file
#define AT(type, file, offset) ((type*) at(file, offset, sizeof(type)))
// Checks if the array element is within the file && idx is within given bound
#define AT_ARR(type, file, offset, arr_sz, idx) ((type*) at_arr(file, offset, sizeof(type), arr_sz, idx))
// Checks if the whole array is within the file
#define AT_ARR_FULL(type, file, offset, arr_sz) ((type*) at(file, offset, sizeof(type)))

// ELF accessors
Elf64_Ehdr* elf_hdr(MemFile* elf);
Elf64_Shdr* elf_shdr(MemFile* elf, size_t idx);
Elf64_Phdr* elf_phdr(MemFile* elf, size_t idx);
size_t elf_shdr_cnt(MemFile* elf);
size_t elf_phdr_cnt(MemFile* elf);

// More complex accessors
size_t elf_get_program_alignment(MemFile* elf, Elf64_Word program_type);
Elf64_Word elf_section_flags_to_program_flags(Elf64_Xword sflags);
Elf64_Addr elf_get_free_vaddr(MemFile* elf, size_t alignment);

// Util functions
uint64_t align_to(uint64_t alignment, uint64_t value);
size_t file_get_size(FILE* file);

// Main functions
bool memfile_read(MemFile* file);
bool memfile_write(MemFile* file);
void memfile_drop(MemFile* file);
bool memfile_paste(MemFile* dst, size_t dst_off, MemFile* src, size_t src_off, size_t size);

bool elf_check_sanity(MemFile* elf, Elf64_Half expected_type);
bool elf_link(MemFile* out, MemFile* exec, MemFile* rel);

int main(int argc, char** argv) 
{
	int status = 1;
	MemFile exec = {0};
	MemFile rel = {0};
	MemFile out = {0};

	if (argc != 4) {	
		fprintf(stderr, "usage: %s <ET_EXEC> <ET_REL> <target ET_EXEC>\n", argv[0]);
		goto cleanup;
	}

	exec.path = argv[1];
	rel.path = argv[2];
	out.path = argv[3];

	if (!memfile_read(&exec) || !memfile_read(&rel)) {
		goto cleanup;
	}

	if(!elf_check_sanity(&exec, ET_EXEC)
	|| !elf_check_sanity(&rel, ET_REL)) {
		goto cleanup;
	}

	if (!elf_link(&out, &exec, &rel)) {
		goto cleanup;
	}

	if (!memfile_write(&out)) {
		goto cleanup;
	}

	status = 0;

cleanup:
	memfile_drop(&exec);
	memfile_drop(&rel);
	memfile_drop(&out);

	return status;
}


char* at(MemFile* file, size_t offset, size_t elemsize) {
	bool valid = (file->addr != NULL) && (offset + elemsize <= file->size);
	if (!valid) {
		fprintf(stderr, "%s: illegal access @ (%zu:%zu) (file size = %zu)\n",
		        file->path, offset, offset + elemsize, file->size);
		exit(1);
	}
	return (char*) file->addr + offset;
}


char* at_arr(MemFile* file, size_t offset, size_t elemsize, size_t arr_sz, size_t idx) {
	if (idx >= arr_sz) {
		fprintf(stderr, "%s: out of bounds array access @%zu[%zu >= %zu]\n",
		        file->path, offset, idx, arr_sz);
		exit(1);
	}
	return at(file, offset + idx * elemsize, elemsize);
}


Elf64_Ehdr* elf_hdr(MemFile* elf) {
	return AT(Elf64_Ehdr, elf, 0);
}


Elf64_Shdr* elf_shdr(MemFile* elf, size_t idx) {
	Elf64_Ehdr* hdr = elf_hdr(elf);
	return AT_ARR(Elf64_Shdr, elf, hdr->e_shoff, hdr->e_shnum, idx);
}


Elf64_Phdr* elf_phdr(MemFile* elf, size_t idx) {
	Elf64_Ehdr* hdr = elf_hdr(elf);
	return AT_ARR(Elf64_Phdr, elf, hdr->e_phoff, hdr->e_phnum, idx);
}


size_t elf_shdr_cnt(MemFile* elf) {
	Elf64_Ehdr* hdr = elf_hdr(elf);
	if (hdr->e_shnum == SHN_UNDEF) {
		Elf64_Shdr* shdr = AT_ARR(Elf64_Shdr, elf, hdr->e_shoff, hdr->e_shnum, 0);
		return (size_t) shdr->sh_size;
	}
	return (size_t) hdr->e_shnum;
}


size_t elf_phdr_cnt(MemFile* elf) {
	return (size_t) elf_hdr(elf)->e_phnum;
}


// const char* elf_str(MemFile* elf, size_t idx) {
// 	abort(); // TODO
// 	// elf->strtab = NULL;
// 	// elf->strtab_size = 0;
// 	// Elf64_Word str_idx = elf->hdr->e_shstrndx;
// 	// if (str_idx != SHN_UNDEF) {
// 	// 	if (elf->hdr->e_shstrndx == SHN_XINDEX) {
// 	// 		str_idx = elf->shdr[0].sh_link;
// 	// 	}

// 	// 	elf->strtab = (const char*) elf_bytes + elf->shdr[str_idx].sh_offset;
// 	// 	elf->strtab_size = elf->shdr[str_idx].sh_size;
// 	// }
// }


// Elf64_Sym* elf_sym(MemFile* elf, size_t idx) {
// 	abort(); // TODO
// 	// elf->sym = NULL;
// 	// for (Elf64_Section i = 0; i < elf->hdr->e_shnum; ++i) {
// 	// 	if (elf->shdr[i].sh_type == SHT_SYMTAB) {
// 	// 		if (elf->shdr[i].sh_entsize != sizeof(Elf64_Sym)) {
// 	// 			fprintf(stderr, "%s: invalid symtab entry size (%zu != %zu)\n",
// 	// 			        elf->path, (size_t) elf->shdr[i].sh_entsize, sizeof(Elf64_Sym));
// 	// 			return false;
// 	// 		}
// 	// 		elf->sym = (Elf64_Sym*) elf_bytes + elf->shdr[i].sh_offset;
// 	// 		elf->sym_count = elf->shdr[i].sh_size / elf->shdr[i].sh_entsize;
// 	// 		break;
// 	// 	}
// 	// }
// }


// const char* elf_section_name(MemFile* elf, Elf64_Half idx) {
// 	abort(); // TODO
// 	// return elf->strtab + elf->shdr[idx].sh_name;
// }


size_t elf_get_program_alignment(MemFile* elf, Elf64_Word program_type)
{
	for (size_t i = 0; i < elf_phdr_cnt(elf); i++) {
		Elf64_Phdr* phdr = elf_phdr(elf, i);
		if (phdr->p_type == program_type) {
			return phdr->p_align;
		}
	}
	return 1;
}


Elf64_Word elf_section_flags_to_program_flags(Elf64_Xword sflags)
{
	Elf64_Word program = 0;
	program |= PF_R;
	program |= (sflags & SHF_WRITE) ? PF_W : 0;
	program |= (sflags & SHF_EXECINSTR) ? PF_X : 0;
	return program;
}


Elf64_Addr elf_get_free_vaddr(MemFile* elf, size_t alignment)
{
	Elf64_Addr highest = 0;
	for (size_t i = 0; i < elf_phdr_cnt(elf); i++) {
		Elf64_Phdr* phdr = elf_phdr(elf, i);
		Elf64_Addr candidate = phdr->p_vaddr + phdr->p_memsz;
		highest = candidate > highest ? candidate : highest;
	}
	return align_to(alignment, highest);
}

uint64_t align_to(uint64_t alignment, uint64_t value)
{
	return (alignment <= 1) ? value : value + (alignment - (value % alignment));
}

bool memfile_read(MemFile* file)
{
	FILE* stream = NULL;
	void* addr = NULL;
	bool status = false;
	
	stream = fopen(file->path, "r");
	if (NULL == stream) {
		fprintf(stderr, "%s: failed to open: %s\n", file->path, strerror(errno));
		goto cleanup;
	}

	// Get file size
	if (0 != fseek(stream, 0, SEEK_END)) {
		fprintf(stderr, "%s: failed to get file size (fseek): %s\n", file->path, strerror(errno));
		goto cleanup;
	}

	long ssize = ftell(stream);
	if (-1L == ssize) {
		fprintf(stderr, "%s: failed to get file size (ftell): %s\n", file->path, strerror(errno));
		goto cleanup;
	}
	file->size = (size_t) ssize;

	if (0 != fseek(stream, 0, SEEK_SET)) {
		fprintf(stderr, "%s: failed to get file size (fseek): %s\n", file->path, strerror(errno));
		goto cleanup;
	}

	addr = malloc(file->size);
	if (NULL == addr) {
		fprintf(stderr, "%s: failed to read: out of memory\n", file->path);
		goto cleanup;
	}
	file->addr = addr;

	if (file->size > fread(file->addr, 1, file->size, stream)) {
		fprintf(stderr, "%s: failed to read: fread\n", file->path);
		goto cleanup;
	}

	status = true;
	addr = NULL;

cleanup:
	if (stream != NULL) {
		fclose(stream);
	}
	if (addr != NULL) {
		free(addr);
	}
	return status;
}

bool memfile_write(MemFile* file)
{
	bool status = false;
	FILE* stream = NULL;

	stream = fopen(file->path, "wb");
	if (NULL == stream) {
		fprintf(stderr, "%s: failed to write file: %s\n", file->path, strerror(errno));
		goto cleanup;
	}

	if (file->size > fwrite(file->addr, 1, file->size, stream)) {
		fprintf(stderr, "%s: failed to write: fwrite\n", file->path);
		goto cleanup;
	}

	status = true;

cleanup:
	if (stream != NULL) {
		fclose(stream);
	}
	return status;
}

void memfile_drop(MemFile* file)
{
	if (file->addr != NULL) {
		free(file->addr);
		file->addr = NULL;
	}
}

bool memfile_paste(MemFile* dst, size_t dst_off, MemFile* src, size_t src_off, size_t size) {
	if (dst_off + size > dst->size) {
		dst->addr = realloc(dst->addr, dst_off + size);
		if (NULL == dst->addr) {
			return false;
		}
		// Init new memory chunk
		memset((char*) dst->addr + dst->size, 0, (dst_off + size) - dst->size);
		dst->size = dst_off + size;
	}
	memcpy(
		at(dst, dst_off, size),
		at(src, src_off, size),
		size
	);
	return true;
}


bool elf_check_sanity(MemFile* elf, Elf64_Half expected_type)
{
	Elf64_Ehdr* hdr = elf_hdr(elf);

	// Ident
	bool magic_ok = hdr->e_ident[EI_MAG0]  == ELFMAG0
	             && hdr->e_ident[EI_MAG1]  == ELFMAG1
	             && hdr->e_ident[EI_MAG2]  == ELFMAG2
	             && hdr->e_ident[EI_MAG3]  == ELFMAG3;
	bool class_ok = hdr->e_ident[EI_CLASS] == ELFCLASS64;
	bool data_ok  = hdr->e_ident[EI_DATA]  == ELFDATA2LSB;
	if (!(magic_ok && class_ok && data_ok)) {
		fprintf(stderr, "%s: invalid header (magic: %d, class: %d, data: %d)\n", 
		        elf->path, magic_ok, class_ok, data_ok);
		return false;
	}
	
	// Type: rel/exec
	if (hdr->e_type != expected_type) {
		fprintf(stderr, "%s: expected elf type %hu, found %hu\n", elf->path, expected_type, hdr->e_type);
		return false;
	}

	// Machine: x86_64
	const Elf64_Half expected_machine = EM_X86_64;
	if (hdr->e_machine != expected_machine) {
		fprintf(stderr, "%s: expected elf machine %hu, found %hu\n", elf->path, expected_machine, hdr->e_machine);
		return false;
	}

	// Shdr binary compability 
	if (hdr->e_shnum > 0 && hdr->e_shentsize != sizeof(Elf64_Shdr)) {
		fprintf(stderr, "%s: invalid section entry size (%zu != %zu)\n", 
		        elf->path, sizeof(Elf64_Shdr), (size_t) hdr->e_shentsize);
		return false;
	}

	// Phdr binary compability
	if (hdr->e_phnum > 0 && hdr->e_phentsize != sizeof(Elf64_Phdr)) {
		fprintf(stderr, "%s: invalid segment entry size (%zu != %zu)\n",
		        elf->path, (size_t) hdr->e_shentsize, sizeof(Elf64_Shdr));
		return false;
	}

	// Shdr presence
	if (hdr->e_shoff < hdr->e_ehsize || hdr->e_shnum == 0) {
		fprintf(stderr, "%s: no sections found\n", elf->path);
		return false;
	}

	// Phdr presence
	if (hdr->e_type == ET_EXEC && (hdr->e_phoff < hdr->e_ehsize || hdr->e_phnum == 0)) {
		fprintf(stderr, "%s: no segments found\n", elf->path);
		return false;
	}

	// TODO verify if it's needed / guaranteed by ELF
	// Verify assumption that there's nothing between Ehdr and Phdr:
	if (hdr->e_type == ET_EXEC && hdr->e_phoff != sizeof(Elf64_Ehdr)) {
		fprintf(stderr, "%s: program header not directly after elf header (%zu != %zu)\n", 
		        elf->path, hdr->e_phoff, sizeof(Elf64_Ehdr));
		return false;
	}

	return true;
}


typedef struct
{
	Elf64_Half orig_idx;
	Elf64_Xword acc_flags;
} SectionFlagsIdx;

static 
int elf_section_flags_cmp(const void* void_lhs, const void* void_rhs)
{
	const SectionFlagsIdx* lhs = void_lhs;
	const SectionFlagsIdx* rhs = void_rhs;
	return (lhs->acc_flags < rhs->acc_flags) ? -1 : lhs->acc_flags > rhs->acc_flags;
}

bool elf_link(MemFile* out, MemFile* exec, MemFile* rel)
{
	bool status = false;
	SectionFlagsIdx* alloc_sect = NULL;
	
	// Group SHF_ALLOC sections in ET_REL: sort by (flags & (SHF_WRITE | SHF_EXECINSTR))
	size_t alloc_shdr_cnt = 0;
	alloc_sect = malloc(elf_shdr_cnt(rel) * sizeof(*alloc_sect));
	if (NULL == alloc_sect) {
		fprintf(stderr, "%s: failed to sort sections: out of memory\n", out->path);
		goto cleanup;
	}
	for (size_t i = 0; i < elf_shdr_cnt(rel); ++i) {
		Elf64_Shdr* shdr = elf_shdr(rel, i);
		if (shdr->sh_flags & SHF_ALLOC) {
			alloc_sect[alloc_shdr_cnt].orig_idx = i;
			alloc_sect[alloc_shdr_cnt].acc_flags = (SHF_WRITE | SHF_EXECINSTR) & shdr->sh_flags;
			alloc_shdr_cnt += 1;
		}
	}
	qsort(alloc_sect, alloc_shdr_cnt, sizeof(*alloc_sect), elf_section_flags_cmp);
	
	// Get number of new program headers
	size_t new_phdr_cnt = (alloc_shdr_cnt > 0);
	for (size_t i = 1; i < alloc_shdr_cnt; ++i) {
		if (alloc_sect[i].acc_flags != alloc_sect[i-1].acc_flags) {
			new_phdr_cnt += 1;
		}
	}

	size_t out_offset = 0;

	// Copy the elf header and program headers
	size_t ehdr_phdr_size = sizeof(Elf64_Ehdr) + elf_hdr(exec)->e_phentsize * elf_phdr_cnt(exec);
	if (!memfile_paste(out, out_offset, exec, 0, ehdr_phdr_size)) {
		goto cleanup;
	}
	out_offset += ehdr_phdr_size;
	
	// Make space for new program headers
	size_t new_phdr_size = new_phdr_cnt * elf_hdr(exec)->e_phentsize;
	out_offset += new_phdr_size;
	
	// Paste the old file content after the new program headers
	out_offset = align_to(sysconf(_SC_PAGE_SIZE), out_offset);
	size_t bytes_prepended = out_offset;
	if (!memfile_paste(out, out_offset, exec, 0, exec->size)) {
		goto cleanup;
	}
	out_offset += exec->size;

	// Fix ELF header
	Elf64_Ehdr* hdr = elf_hdr(out);
	hdr->e_shoff += bytes_prepended;

	// Fix section headers
	for (size_t i = 0; i < elf_shdr_cnt(out); ++i) {
		Elf64_Shdr* shdr = elf_shdr(out, i);
		shdr->sh_offset += bytes_prepended;
	}	

	bool phdr_seen = false;
	bool load_seen = false;
	// Fix old segments' file offsets, vaddr and sizes
	for (size_t i = 0; i < elf_phdr_cnt(exec); ++i) {
		Elf64_Phdr* curr_phdr = elf_phdr(out, i);
		// Correct vaddr in PT_PHDR 
		if (!phdr_seen && curr_phdr->p_type == PT_PHDR) {
			curr_phdr->p_vaddr -= bytes_prepended;
			curr_phdr->p_paddr -= bytes_prepended;
			phdr_seen = true;
			continue;
		}
		// Correct vaddr and size in the first PT_LOAD
		if (!load_seen && curr_phdr->p_type == PT_LOAD) {
			curr_phdr->p_vaddr  -= bytes_prepended;
			curr_phdr->p_paddr  -= bytes_prepended;
			curr_phdr->p_filesz += bytes_prepended;
			curr_phdr->p_memsz  += bytes_prepended;
			load_seen = true;
			continue;
		}
		// Correct offset: all except first PT_LOAD and PT_PHDR
		curr_phdr->p_offset += bytes_prepended;
	}

	// Paste all the allocatable sections at the end of the output file
	Elf64_Xword prev_flags = SHF_MASKOS; // anything that's != alloc_sect[0].sh_flags

	for (size_t alloc_shdr_idx = 0; alloc_shdr_idx < alloc_shdr_cnt; ++alloc_shdr_idx) {
		// Copy current section
		Elf64_Shdr* shdr = elf_shdr(rel, alloc_sect[alloc_shdr_idx].orig_idx);
		out_offset = align_to(shdr->sh_addralign, out_offset);
		if (!memfile_paste(out, out_offset, rel, shdr->sh_offset, shdr->sh_size)) {
			goto cleanup;
		}

		// Detect section belonging to a next segment (with different access attributes).
		// This is always taken on the first loop pass.
		if (alloc_sect[alloc_shdr_idx].acc_flags != prev_flags) {
			hdr->e_phnum += 1;
			Elf64_Phdr* curr_phdr = elf_phdr(out, elf_phdr_cnt(out) - 1);
			curr_phdr->p_type = PT_LOAD;
			curr_phdr->p_offset = out_offset;
			curr_phdr->p_filesz = 0;
			curr_phdr->p_memsz = 0;
			curr_phdr->p_flags = elf_section_flags_to_program_flags(alloc_sect[alloc_shdr_idx].acc_flags);
			curr_phdr->p_align = elf_get_program_alignment(exec, PT_LOAD);
			curr_phdr->p_vaddr = curr_phdr->p_paddr = curr_phdr->p_offset + elf_get_free_vaddr(out, curr_phdr->p_align);
			// TODO update vaddr, maybe phnum can be increased in 
		}
		out_offset += shdr->sh_size;

		// Update current segment's size
		Elf64_Phdr* curr_phdr = elf_phdr(out, elf_phdr_cnt(out) - 1);
		curr_phdr->p_filesz += shdr->sh_size;
		curr_phdr->p_memsz  += shdr->sh_size;

		prev_flags = alloc_sect[alloc_shdr_idx].acc_flags;
	}

	status = true;

cleanup:
	if (NULL != alloc_sect){
		free(alloc_sect);
	}

	return status;
}
