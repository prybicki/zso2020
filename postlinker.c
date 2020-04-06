#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include <unistd.h>
#include <elf.h>

typedef struct {
	const char* path;
	void* addr;
	size_t size;
} MemFile;

typedef struct{
	Elf64_Half orig_idx;
	Elf64_Xword acc_flags;
	Elf64_Addr vaddr;
	Elf64_Off file_off;
} AllocSectionInfo;

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

const char* elf_shstrtab_str(MemFile* elf, size_t idx);
Elf64_Shdr* elf_strtab(MemFile* elf);
const char* elf_strtab_str(MemFile* elf, Elf64_Shdr* strtab_shdr, size_t idx);

Elf64_Shdr* elf_sym_shdr(MemFile* elf);
Elf64_Sym* elf_sym(MemFile* elf, Elf64_Shdr* syms_shdr, size_t sym_idx);
size_t elf_sym_cnt(Elf64_Shdr* syms_shdr);
const char* elf_sym_name(MemFile* elf, Elf64_Shdr* syms_shdr, size_t sym_idx);
Elf64_Sym* elf_sym_with_name(MemFile* elf, Elf64_Shdr* syms_shdr, const char* name);
Elf64_Sym* elf_sym_with_name_try(MemFile* elf, Elf64_Shdr* syms_shdr, const char* name);

Elf64_Rela* elf_rela(MemFile* elf, Elf64_Shdr* rela_shdr, size_t rela_idx);
size_t elf_rela_cnt(Elf64_Shdr* rela_shdr);

// ELF util functions
size_t elf_get_program_alignment(MemFile* elf, Elf64_Word program_type);
Elf64_Word elf_section_flags_to_program_flags(Elf64_Xword sflags);
Elf64_Addr elf_get_free_vaddr(MemFile* elf, size_t alignment);

// ELF main functions
bool elf_check_sanity(MemFile* elf, Elf64_Half expected_type);
bool elf_group_sections(MemFile* elf, AllocSectionInfo** out_alloc, size_t* out_sect_cnt, size_t* out_new_phdr_cnt);
bool elf_merge(MemFile* out, MemFile* exec, MemFile* rel, AllocSectionInfo* alloc_sect, size_t alloc_sect_cnt, size_t new_phdr_cnt);
bool elf_reloc(MemFile* out, MemFile* rel, AllocSectionInfo* alloc_sect, size_t alloc_sect_cnt);

// Util functions
uint64_t align_to(uint64_t alignment, uint64_t value);
AllocSectionInfo* alloc_find_idx(AllocSectionInfo* arr, size_t count, Elf64_Half orig_idx);
bool copy_file_permissions(const char* dst_path, const char* src_path);

// Memfile functions
bool memfile_read(MemFile* file);
bool memfile_write(MemFile* file);
void memfile_drop(MemFile* file);
bool memfile_paste(MemFile* dst, size_t dst_off, MemFile* src, size_t src_off, size_t size);


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

	if (!elf_check_sanity(&exec, ET_EXEC)
	||  !elf_check_sanity(&rel, ET_REL)) {
		goto cleanup;
	}

	if (NULL == elf_sym_with_name_try(&rel, elf_sym_shdr(&rel), "_start")) {
		memfile_paste(&out, 0, &exec, 0, exec.size);
		status = true;
		goto cleanup;
	}

	AllocSectionInfo* alloc_sect = NULL;
	size_t alloc_sect_cnt = 0;
	size_t new_phdr_cnt = 0;
	if (!elf_group_sections(&rel, &alloc_sect, &alloc_sect_cnt, &new_phdr_cnt)) {
		goto cleanup;
	}

	if (!elf_merge(&out, &exec, &rel, alloc_sect, alloc_sect_cnt, new_phdr_cnt)) {
		goto cleanup;
	}

	if (!elf_reloc(&out, &rel, alloc_sect, alloc_sect_cnt)) {
		goto cleanup;
	}

	if (!memfile_write(&out)) {
		goto cleanup;
	}

	status = 0;

cleanup:
	if (alloc_sect != NULL) {
		free(alloc_sect);
		alloc_sect = NULL;
	}
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
		exit(EXIT_FAILURE);
	}
	return (char*) file->addr + offset;
}


char* at_arr(MemFile* file, size_t offset, size_t elemsize, size_t arr_sz, size_t idx) {
	if (idx >= arr_sz) {
		fprintf(stderr, "%s: out of bounds array access @%zu[%zu >= %zu]\n",
		        file->path, offset, idx, arr_sz);
		exit(EXIT_FAILURE);
	}
	return at(file, offset + idx * elemsize, elemsize);
}


Elf64_Ehdr* elf_hdr(MemFile* elf) {
	return AT(Elf64_Ehdr, elf, 0);
}


Elf64_Shdr* elf_shdr(MemFile* elf, size_t idx) {
	Elf64_Ehdr* out_hdr = elf_hdr(elf);
	return AT_ARR(Elf64_Shdr, elf, out_hdr->e_shoff, out_hdr->e_shnum, idx);
}


Elf64_Phdr* elf_phdr(MemFile* elf, size_t idx) {
	Elf64_Ehdr* out_hdr = elf_hdr(elf);
	return AT_ARR(Elf64_Phdr, elf, out_hdr->e_phoff, out_hdr->e_phnum, idx);
}


size_t elf_shdr_cnt(MemFile* elf) {
	Elf64_Ehdr* out_hdr = elf_hdr(elf);
	if (out_hdr->e_shnum == SHN_UNDEF) {
		Elf64_Shdr* shdr = AT_ARR(Elf64_Shdr, elf, out_hdr->e_shoff, out_hdr->e_shnum, 0);
		return (size_t) shdr->sh_size;
	}
	return (size_t) out_hdr->e_shnum;
}


size_t elf_phdr_cnt(MemFile* elf) {
	return (size_t) elf_hdr(elf)->e_phnum;
}


Elf64_Shdr* elf_sym_shdr(MemFile* elf) {
	for (size_t i = 0; i < elf_shdr_cnt(elf); ++i) {
		Elf64_Shdr* shdr = elf_shdr(elf, i);
		if (shdr->sh_type == SHT_SYMTAB) {
			return shdr; // All checks done in elf_shdr
		}
	}
	fprintf(stderr, "%s: no symtab found\n", elf->path);
	exit(EXIT_FAILURE);
}


Elf64_Sym* elf_sym(MemFile* elf, Elf64_Shdr* syms_shdr, size_t sym_idx) {
	return AT_ARR(Elf64_Sym, elf, syms_shdr->sh_offset, elf_sym_cnt(syms_shdr), sym_idx);
}


size_t elf_sym_cnt(Elf64_Shdr* syms_shdr) {
	return syms_shdr->sh_size / syms_shdr->sh_entsize;
}


const char* elf_shstrtab_str(MemFile* elf, size_t idx) {
	Elf64_Shdr* strtab = elf_shdr(elf, elf_hdr(elf)->e_shstrndx);
	return AT_ARR(const char, elf, strtab->sh_offset, strtab->sh_size, idx);
}

Elf64_Shdr* elf_strtab(MemFile* elf) {
	for (size_t i = 0; i < elf_shdr_cnt(elf); ++i) {
		const char* sect_name = elf_shstrtab_str(elf, elf_shdr(elf, i)->sh_name);
		if (0 == strcmp(".strtab", sect_name)) {
			return elf_shdr(elf, i);
		}
	}
	fprintf(stderr, "%s: strtab not found\n", elf->path);
	exit(EXIT_FAILURE);
}

const char* elf_strtab_str(MemFile* elf, Elf64_Shdr* strtab_shdr, size_t idx) {
	return AT_ARR(const char, elf, strtab_shdr->sh_offset, strtab_shdr->sh_size, idx);
}


const char* elf_sym_name(MemFile* elf, Elf64_Shdr* syms_shdr, size_t sym_idx) {
	return elf_strtab_str(elf, elf_strtab(elf), elf_sym(elf, syms_shdr, sym_idx)->st_name);
}


Elf64_Sym* elf_sym_with_name_try(MemFile* elf, Elf64_Shdr* syms_shdr, const char* name) {
	for (size_t i = 0; i < elf_sym_cnt(syms_shdr); ++i) {
		if (0 == strcmp(name, elf_sym_name(elf, syms_shdr, i))) {
			return AT_ARR(Elf64_Sym, elf, syms_shdr->sh_offset, elf_sym_cnt(syms_shdr), i);
		}
	}
	return NULL;
}


Elf64_Sym* elf_sym_with_name(MemFile* elf, Elf64_Shdr* syms_shdr, const char* name) {
	Elf64_Sym* result = elf_sym_with_name_try(elf, syms_shdr, name);
	if (NULL == result) {
		fprintf(stderr, "%s: could not find symbol named \"%s\"\n", elf->path, name);
		exit(EXIT_FAILURE);
	}
	return result;
}

Elf64_Rela* elf_rela(MemFile* elf, Elf64_Shdr* rela_shdr, size_t rela_idx) {
	return AT_ARR(Elf64_Rela, elf, rela_shdr->sh_offset, elf_rela_cnt(rela_shdr), rela_idx);
}

size_t elf_rela_cnt(Elf64_Shdr* rela_shdr) {
	return rela_shdr->sh_size / rela_shdr->sh_entsize;
}

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
	if (alignment <= 1 || value % alignment == 0) {
		return value;
	}
	return value + (alignment - (value % alignment));
}

AllocSectionInfo* alloc_find_idx(AllocSectionInfo* arr, size_t count, Elf64_Half orig_idx)
{
	for (size_t i = 0; i < count; ++i) {
		if (arr[i].orig_idx == orig_idx) {
			return arr + i;
		}
	}
	fprintf(stderr, "could not find alloc_sect section with orig_idx=%hu\n", orig_idx);
	exit(EXIT_FAILURE);
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
	Elf64_Ehdr* out_hdr = elf_hdr(elf);

	// Ident
	bool magic_ok = out_hdr->e_ident[EI_MAG0]  == ELFMAG0
	             && out_hdr->e_ident[EI_MAG1]  == ELFMAG1
	             && out_hdr->e_ident[EI_MAG2]  == ELFMAG2
	             && out_hdr->e_ident[EI_MAG3]  == ELFMAG3;
	bool class_ok = out_hdr->e_ident[EI_CLASS] == ELFCLASS64;
	bool data_ok  = out_hdr->e_ident[EI_DATA]  == ELFDATA2LSB;
	if (!(magic_ok && class_ok && data_ok)) {
		fprintf(stderr, "%s: invalid header (magic: %d, class: %d, data: %d)\n", 
		        elf->path, magic_ok, class_ok, data_ok);
		return false;
	}
	
	// Type: rel/exec
	if (out_hdr->e_type != expected_type) {
		fprintf(stderr, "%s: expected elf type %hu, found %hu\n", elf->path, expected_type, out_hdr->e_type);
		return false;
	}

	// Machine: x86_64
	const Elf64_Half expected_machine = EM_X86_64;
	if (out_hdr->e_machine != expected_machine) {
		fprintf(stderr, "%s: expected elf machine %hu, found %hu\n", elf->path, expected_machine, out_hdr->e_machine);
		return false;
	}

	// Shdr binary compability 
	if (out_hdr->e_shnum > 0 && out_hdr->e_shentsize != sizeof(Elf64_Shdr)) {
		fprintf(stderr, "%s: invalid section entry size (%zu != %zu)\n", 
		        elf->path, sizeof(Elf64_Shdr), (size_t) out_hdr->e_shentsize);
		return false;
	}

	// Phdr binary compability
	if (out_hdr->e_phnum > 0 && out_hdr->e_phentsize != sizeof(Elf64_Phdr)) {
		fprintf(stderr, "%s: invalid segment entry size (%zu != %zu)\n",
		        elf->path, (size_t) out_hdr->e_shentsize, sizeof(Elf64_Shdr));
		return false;
	}

	// Shdr presence
	if (out_hdr->e_shoff < out_hdr->e_ehsize || out_hdr->e_shnum == 0) {
		fprintf(stderr, "%s: no sections found\n", elf->path);
		return false;
	}

	// Phdr presence
	if (out_hdr->e_type == ET_EXEC && (out_hdr->e_phoff < out_hdr->e_ehsize || out_hdr->e_phnum == 0)) {
		fprintf(stderr, "%s: no segments found\n", elf->path);
		return false;
	}

	// TODO verify if it's needed / guaranteed by ELF
	// Verify assumption that there's nothing between Ehdr and Phdr:
	if (out_hdr->e_type == ET_EXEC && out_hdr->e_phoff != sizeof(Elf64_Ehdr)) {
		fprintf(stderr, "%s: program header not directly after elf header (%zu != %zu)\n", 
		        elf->path, out_hdr->e_phoff, sizeof(Elf64_Ehdr));
		return false;
	}

	return true;
}

static 
int elf_section_flags_cmp(const void* void_lhs, const void* void_rhs)
{
	const AllocSectionInfo* lhs = void_lhs;
	const AllocSectionInfo* rhs = void_rhs;
	return (lhs->acc_flags < rhs->acc_flags) ? -1 : lhs->acc_flags > rhs->acc_flags;
}

bool elf_group_sections(MemFile* elf, AllocSectionInfo** out_alloc, size_t* out_sect_cnt, size_t* out_new_phdr_cnt)
{
	AllocSectionInfo* alloc_sect = NULL; // for internal use
	*out_alloc = NULL;
	*out_sect_cnt = 0;
	*out_new_phdr_cnt = 0;

	// alloc_sect space to fit all the sections in the file.
	*out_alloc = malloc(elf_shdr_cnt(elf) * sizeof(**out_alloc));
	if (NULL == *out_alloc) {
		fprintf(stderr, "%s: failed to sort sections: out of memory\n", elf->path);
		return false;
	}
	alloc_sect = *out_alloc;

	// Collect relevant info about sections
	for (size_t i = 0; i < elf_shdr_cnt(elf); ++i) {
		Elf64_Shdr* shdr = elf_shdr(elf, i);
		if (shdr->sh_flags & SHF_ALLOC) {
			alloc_sect[*out_sect_cnt].orig_idx = i;
			alloc_sect[*out_sect_cnt].acc_flags = (SHF_WRITE | SHF_EXECINSTR) & shdr->sh_flags;
			*out_sect_cnt += 1;
		}
	}
	// Sort by (flags & (SHF_WRITE | SHF_EXECINSTR))
	qsort(alloc_sect, *out_sect_cnt, sizeof(*alloc_sect), elf_section_flags_cmp);
	
	// Get number of new program headers
	*out_new_phdr_cnt = (*out_sect_cnt > 0);
	for (size_t i = 1; i < *out_sect_cnt; ++i) {
		if (alloc_sect[i].acc_flags != alloc_sect[i-1].acc_flags) {
			*out_new_phdr_cnt += 1;
		}
	}

	return true;
}

bool elf_merge(MemFile* out, MemFile* exec, MemFile* rel, AllocSectionInfo* alloc_sect, size_t alloc_sect_cnt, size_t new_phdr_cnt)
{
	size_t out_offset = 0;

	// Copy the elf header and program headers
	size_t ehdr_phdr_size = sizeof(Elf64_Ehdr) + elf_hdr(exec)->e_phentsize * elf_phdr_cnt(exec);
	if (!memfile_paste(out, out_offset, exec, 0, ehdr_phdr_size)) {
		return false;
	}
	out_offset += ehdr_phdr_size;
	
	// Make space for new program headers
	size_t new_phdr_size = new_phdr_cnt * elf_hdr(exec)->e_phentsize;
	out_offset += new_phdr_size;
	
	// Paste the old file content after the new program headers
	out_offset = align_to(sysconf(_SC_PAGE_SIZE), out_offset);
	size_t bytes_prepended = out_offset;
	if (!memfile_paste(out, out_offset, exec, 0, exec->size)) {
		return false;
	}
	out_offset += exec->size;

	// Fix ELF header
	elf_hdr(out)->e_shoff += bytes_prepended;

	// Fix section headers
	for (size_t i = 0; i < elf_shdr_cnt(out); ++i) {
		elf_shdr(out, i)->sh_offset += bytes_prepended;
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
	Elf64_Addr curr_section_vaddr_offset = 0; // offset of section first byte from current segment
	for (size_t alloc_idx = 0; alloc_idx < alloc_sect_cnt; ++alloc_idx) {
		// Copy current section
		Elf64_Shdr* shdr = elf_shdr(rel, alloc_sect[alloc_idx].orig_idx);
		out_offset = align_to(shdr->sh_addralign, out_offset);
		if (!memfile_paste(out, out_offset, rel, shdr->sh_offset, shdr->sh_size)) {
			return false;
		}

		// Detect section belonging to a next segment (with different access attributes).
		// This is always taken on the first loop pass.
		if (alloc_sect[alloc_idx].acc_flags != prev_flags) {
			// printf("New phdr\n");
			elf_hdr(out)->e_phnum += 1;
			curr_section_vaddr_offset = 0;
			Elf64_Phdr* curr_phdr = elf_phdr(out, elf_phdr_cnt(out) - 1);
			curr_phdr->p_type = PT_LOAD;
			curr_phdr->p_offset = out_offset;
			curr_phdr->p_filesz = 0;
			curr_phdr->p_memsz = 0;
			curr_phdr->p_flags = elf_section_flags_to_program_flags(alloc_sect[alloc_idx].acc_flags);
			curr_phdr->p_align = elf_get_program_alignment(exec, PT_LOAD);
			curr_phdr->p_vaddr = curr_phdr->p_paddr = curr_phdr->p_offset + elf_get_free_vaddr(out, curr_phdr->p_align);
		}
		// printf("%s: 0x%zx\n", elf_shstrtab_str(rel, elf_shdr(rel, alloc_sect[alloc_idx].orig_idx)->sh_name), out_offset);
		Elf64_Phdr* curr_phdr = elf_phdr(out, elf_phdr_cnt(out) - 1);
		// Update current segment's size
		curr_phdr->p_filesz += shdr->sh_size;
		curr_phdr->p_memsz  += shdr->sh_size;

		alloc_sect[alloc_idx].file_off = out_offset;
		alloc_sect[alloc_idx].vaddr = curr_phdr->p_vaddr + curr_section_vaddr_offset;

		out_offset += shdr->sh_size;
		curr_section_vaddr_offset += shdr->sh_size;

		prev_flags = alloc_sect[alloc_idx].acc_flags;
	}
	return true;
}

bool elf_reloc(MemFile* out, MemFile* rel, AllocSectionInfo* alloc_sect, size_t alloc_sect_cnt)
{
	Elf64_Shdr* out_symtab = elf_sym_shdr(out);
	Elf64_Shdr* rel_symtab = elf_sym_shdr(rel);
	// do relocs
	for (size_t i = 0; i < elf_shdr_cnt(rel); ++i) {
		Elf64_Shdr* shdr = elf_shdr(rel, i);
		if (shdr->sh_type != SHT_RELA) {
			continue;
		}

		Elf64_Shdr* reloc_symtab = elf_shdr(rel, shdr->sh_link);
		Elf64_Section dest_sect_idx = shdr->sh_info;
		
		// TODO
		AllocSectionInfo* dest_info = alloc_find_idx(alloc_sect, alloc_sect_cnt, dest_sect_idx);
				
		for (size_t r = 0; r < elf_rela_cnt(shdr); ++r) {
			Elf64_Rela* rela = elf_rela(rel, shdr, r);
			Elf64_Xword sym_idx = ELF64_R_SYM(rela->r_info);

			Elf64_Addr sym_vaddr = 0;
			const char* sym_name = elf_sym_name(rel, reloc_symtab, sym_idx);
			Elf64_Sym* rel_symbol = elf_sym(rel, reloc_symtab, sym_idx);
			if (rel_symbol->st_shndx != SHN_UNDEF) {
				// Symbol in ET_REL
				AllocSectionInfo* sym_sect_info = alloc_find_idx(alloc_sect, alloc_sect_cnt, rel_symbol->st_shndx);
				sym_vaddr = sym_sect_info->vaddr + elf_sym(rel, reloc_symtab, sym_idx)->st_value;
			}
			else {
				// Symbol in ET_EXEC
				bool its_orig_start = (0 == strcmp("orig_start", sym_name));
				sym_vaddr = its_orig_start ? elf_hdr(out)->e_entry : elf_sym_with_name(out, out_symtab, sym_name)->st_value;
			}

			Elf64_Addr offset = dest_info->file_off + rela->r_offset;
			uint64_t result64 = 0;
			uint32_t result32 = 0;
			switch (ELF64_R_TYPE(rela->r_info)) {
				case R_X86_64_64:
					result64 = sym_vaddr + rela->r_addend;
					memcpy(AT(uint64_t, out, offset), &result64, sizeof(result64));
					break;
				case R_X86_64_32:
					result64 = sym_vaddr + rela->r_addend;
					result32 = (uint32_t) result64;
					memcpy(AT(uint32_t, out, offset), &result32, sizeof(result32));
					break;
				case R_X86_64_32S:
					result64 = sym_vaddr + rela->r_addend;
					result32 = (uint32_t) result64;
					if ((int32_t) result64 != (int64_t) result64) {
						fprintf(stderr, "%s: invalid R_X86_64_32S relocation: symbol \"%s\"\n", out->path, sym_name);
						return false;
					}
					memcpy(AT(uint32_t, out, offset), &result32, sizeof(result32));
					break;
				case R_X86_64_PC32:
				case R_X86_64_PLT32:
					result64 = sym_vaddr - (dest_info->vaddr + rela->r_offset) + rela->r_addend;
					result32 = (uint32_t) result64;
					memcpy(AT(uint32_t, out, offset), &result32, sizeof(result32));
					break;
			}

		}
	}

	Elf64_Sym* start_sym = elf_sym_with_name(rel, rel_symtab, "_start");
	elf_hdr(out)->e_entry = alloc_find_idx(alloc_sect, alloc_sect_cnt, start_sym->st_shndx)->vaddr + start_sym->st_value;
	elf_sym_with_name(out, out_symtab, "_start")->st_value = elf_hdr(out)->e_entry;

	return true;
}