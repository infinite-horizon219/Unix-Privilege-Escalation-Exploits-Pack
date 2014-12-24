/*
 * Copyright (c) 2011, Columbia University
 * All rights reserved.
 *
 * This software was developed by Vasileios P. Kemerlis <vpk@cs.columbia.edu>
 * at Columbia University, New York, NY, USA, in May 2011.
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

/*
 * kernwrite
 *
 * emulates a kernel vulnerability that allows an attacker
 * to overwrite a kernel-mapped data/function pointer with
 * an arbitrary value. It was inspired by Nelson Elhage's
 * NULL pointer dereference module (NULLDEREF)
 *
 * Usage:
 * 	- compile and load the module
 * 	- mount debugfs (mount -t debugfs none /sys/kernel/debug/)
 *	- go to /sys/kernel/debug/kernwrite/ and have fun :)
 */

#include <linux/debugfs.h>
#include <linux/hardirq.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/uaccess.h>

/* buffer size for holding a virtual address */
#if	defined(__i386__)	/* x86 */
#define ADDR_SZ	16		/* 16 bytes */
#elif	defined(__arm__)	/* ARM */
#define ADDR_SZ	16		/* 16 bytes */
#elif	defined(__x86_64__)	/* x86-64 */
#define ADDR_SZ	32		/* 32 bytes */
#endif


/*
 * struct dummy_ops
 *
 * definition of a dummy structure that contains
 * a function pointer and a generic data field
 */
struct dummy_ops {
	size_t val;
	ssize_t (*fptr)(void);
};

/* 
 * a kernel-mapped `dummy_ops' structure
 */
static struct dummy_ops ops;

/* a kernel-mapped data pointer to `ops' */
static struct dummy_ops *ops_ptr;


/*
 * writing to the `over_func_ptr' file overwrites
 * the function pointer of `ops' with an arbitrary,
 * user-controlled value
 */
static ssize_t
over_func(struct file *f, const char __user *buf,
		size_t count, loff_t *off)
{
	/* address buffer */
	char addr[ADDR_SZ];

	/* cleanup */
	memset(addr, 0 , ADDR_SZ);

	/* copy the buffer to kernel space */
	if (copy_from_user(addr,
			buf,
			(count < ADDR_SZ - 1) ? count : ADDR_SZ - 1)  != 0) {
		/* failed */
		printk(KERN_ERR
			"kernwrite: overwriting the function pointer failed\n");
		return -EINVAL;
	}

	/* overwrite the function pointer */
	ops.fptr	= (void *)simple_strtol(addr, NULL, 16);
	f->private_data = ops.fptr;

	/* verbose */
	printk(KERN_DEBUG
	"kernwrite: overwriting function pointer with 0x%p\n", ops.fptr);

	/* done! */
	return count;
}

/*
 * writing to the `over_data_ptr' file overwrites
 * the data pointer to `ops' with an arbitrary,
 * user-controlled value
 */
static ssize_t
over_data(struct file *f, const char __user *buf, size_t count, loff_t *off)
{
	/* address buffer */
	char addr[ADDR_SZ];

	/* cleanup */
	memset(addr, 0 , ADDR_SZ);

	/* copy the buffer to kernel space */
	if (copy_from_user(addr,
			buf,
			(count < ADDR_SZ - 1) ? count : ADDR_SZ - 1)  != 0) {
		/* failed */
		printk(KERN_ERR
			"kernwrite: overwriting the data pointer failed\n");
		return -EINVAL;
	}

	/* overwrite the data pointer */
	ops_ptr		= (void *)simple_strtol(addr, NULL, 16);
	f->private_data = ops_ptr;

	/* verbose */
	printk(KERN_DEBUG
		"kernwrite: overwriting data pointer with 0x%p\n", ops_ptr);

	/* done! */
	return count;
}

/*
 * writing to the `invoke_func' file calls
 * the `fptr' member of `ops' via `opt_ptr'
 */
static ssize_t
invoke_func(struct file *f, const char __user *buf, size_t count, loff_t *off)
{
	/* verbose */
	printk(KERN_DEBUG "kernwrite: executing at 0x%p\n", ops_ptr->fptr);

	/* do it */
	return ops_ptr->fptr();
}


/* handles to the files we will create */
static struct dentry *kernwrite_root	= NULL;
static struct dentry *over_func_ptr	= NULL;
static struct dentry *over_data_ptr	= NULL;
static struct dentry *invoke_func_ptr	= NULL;

/* structs telling the kernel how to handle writes to our files */
static const struct file_operations over_func_fops = {
	.write = over_func,
};
static const struct file_operations over_data_fops = {
	.write = over_data,
};
static const struct file_operations invoke_func_fops = {
	.write = invoke_func,
};


/* module cleanup; remove the files and the directory */
static void
cleanup_debugfs(void)
{
	/* cleanup */
	if (over_func_ptr != NULL)
		debugfs_remove(over_func_ptr);
	if (over_data_ptr != NULL)
		debugfs_remove(over_data_ptr);
	if (invoke_func_ptr != NULL)
		debugfs_remove(invoke_func_ptr);
	if (kernwrite_root != NULL)
		debugfs_remove(kernwrite_root);
}

/* module loading callback */
static int
kernwrite_init(void)
{
	/* initialize the data pointer to `ops' */
	ops_ptr = &ops;

	/* create the kernwrite directory in debugfs */
	kernwrite_root = debugfs_create_dir("kernwrite", NULL);

	/* failed */
	if (kernwrite_root == NULL) {
		/* verbose */
		printk(KERN_ERR "kernwrite: creating root dir failed\n");
		return -ENODEV;
	}

	/* create the files with the appropriate `fops' struct and perms */
	over_func_ptr	= debugfs_create_file("over_func_ptr",
						0222,
						kernwrite_root,
						NULL,
						&over_func_fops);
	
	over_data_ptr	= debugfs_create_file("over_data_ptr",
						0222,
						kernwrite_root,
						NULL,
						&over_data_fops);

	invoke_func_ptr	= debugfs_create_file("invoke_func",
						0222,
						kernwrite_root,
						NULL,
						&invoke_func_fops);

	/* error handling */
	if (over_func_ptr	== NULL	||
		over_data_ptr	== NULL	||
		invoke_func_ptr	== NULL)
		goto out_err;
	
	/* return with success */
	return 0;

out_err:	/* cleanup */
	printk(KERN_ERR "kernwrite: creating files in root dir failed\n");
	cleanup_debugfs();

	/* return with failure */
	return -ENODEV;
}

/* module unloading callback */
static void
kernwrite_exit(void)
{
	cleanup_debugfs();
}


/* register module load/unload callbacks */
module_init(kernwrite_init);
module_exit(kernwrite_exit);

/* (un)necessary crap */
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Vasileios P. Kemerlis <vpk@cs.columbia.edu>");
MODULE_DESCRIPTION("Provides debugfs files to overwrite and dereference a kernel-mapped data/function pointer.");
MODULE_VERSION("2.71alpha");
