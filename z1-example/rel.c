void pisz(const char *str);

void f() {
	pisz("Hello, world!\n");
}

__asm__(
	".global _start\n"
	"_start:\n"
	"push %rdx\n"
	"push %rdx\n"
	"call f\n"
	"pop %rdx\n"
	"pop %rdx\n"
	"jmp orig_start\n"
);
