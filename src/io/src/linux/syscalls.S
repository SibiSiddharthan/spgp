#include <asm/unistd_64.h>
# Only the 64 bit syscalls

.macro sys1 name sys
	.globl \name

	\name:
		mov $\sys, %rax # Move syscall number to rax
		syscall
		ret
.endm

.macro sys2 name sys
	.globl \name

	\name:
		mov $\sys, %rax # Move syscall number to rax
		syscall
		ret
.endm

.macro sys3 name sys
	.globl \name

	\name:
		mov $\sys, %rax # Move syscall number to rax
		syscall
		ret
.endm

.macro sys4 name sys
	.globl \name

	\name:
		mov $\sys, %rax # Move syscall number to rax
		mov %rcx, %r10  # %r10 = %rcx
		syscall
		ret
.endm

.macro sys5 name sys
	.globl \name

	\name:
		mov $\sys, %rax # Move syscall number to rax
		mov %rcx, %r10  # %r10 = %rcx
		syscall
		ret
.endm

.macro sys6 name sys
	.globl \name

	\name:
		mov $\sys, %rax # Move syscall number to rax
		mov %rcx, %r10  # %r10 = %rcx
		syscall
		ret
.endm

# Define the syscalls we need

sys4 lx_open, __NR_openat2
sys1 lx_close, __NR_close

sys3 lx_read, __NR_read
sys3 lx_write, __NR_write
sys3 lx_seek, __NR_lseek

sys5 lx_stat, __NR_statx
sys2 lx_ftruncate, __NR_ftruncate

sys3 lx_mkdir, __NR_mkdirat
sys3 lx_unlink, __NR_unlinkat

sys2 lx_flock, __NR_flock


.section .note.GNU-stack,"",@progbits  # Mark stack as non-executable
