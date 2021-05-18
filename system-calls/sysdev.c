
#include <linux/kernel.h>	/* We're doing kernel work */
#include <linux/module.h>	/* Specifically, a module, */
#include <linux/moduleparam.h>	/* which will have params */
#include <linux/unistd.h>	/* The list of system calls */
#include<linux/kallsyms.h>
#include<linux/init.h>
#include<asm/paravirt.h>
#include<linux/syscalls.h>
#include<linux/kern_levels.h>

/* 
 * For the current (process) structure, we need
 * this to know who the current user is. 
 */
#include <linux/sched.h>
#include <asm/uaccess.h>

#define AUTHOR "NAMAN AGARWAL"
#define DESP "SYSCALL DEVICE"

MODULE_LICENSE("GPL");
MODULE_AUTHOR(AUTHOR);
MODULE_DESCRIPTION(DESP);
MODULE_VERSION("1.0");

void unprotect_memory(void){
	write_cr0(read_cr0() & (~0x10000)); /* set wp flag to 0 */ \
}

void protect_memory(void){
	write_cr0(read_cr0() | 0x10000); /* set wp flag to 1 */ \
}


unsigned long **sys_call_table;


/*static int uid;
module_param(uid, int, 0644);
*/

asmlinkage long (*original_call) (const char *, int, int);

/* 
 * The function we'll replace sys_open (the function
 * called when you call the open system call) with. To
 * find the exact prototype, with the number and type
 * of arguments, we find the original function first
 * (it's at fs/open.c).
 */
 
asmlinkage int our_sys_open(const char *filename, int flags, int mode)
{
	
	/* 
	 * Check if this is the user we're spying on 
	 */
	//if (uid == current->uid) {
		/* 
		 * Report the file, if relevant 
		 */
		printk("Opened file");
	//}

	/* 
	 * Call the original sys_open - otherwise, we lose
	 * the ability to open files 
	 */
	return original_call(filename, flags, mode);
}

/* 
 * Initialize the module - replace the system call 
 */
int init_module()
{
	/* 
	 * Warning - too late for it now, but maybe for
	 * next time... 
	 */
	printk(KERN_ALERT "I'm dangerous. I hope you did a ");
	printk(KERN_ALERT "sync before you insmod'ed me.\n");
	printk(KERN_ALERT "My counterpart, cleanup_module(), is even");
	printk(KERN_ALERT "more dangerous. If\n");
	printk(KERN_ALERT "you value your file system, it will ");
	printk(KERN_ALERT "be \"sync; rmmod\" \n");
	printk(KERN_ALERT "when you remove this module.\n");

	/* 
	 * Keep a pointer to the original function in
	 * original_call, and then replace the system call
	 * in the system call table with our_sys_open 
	 */
	sys_call_table = (unsigned long**)kallsyms_lookup_name("sys_call_table");
	original_call = (void*)sys_call_table[__NR_open];
	unprotect_memory();
	sys_call_table[__NR_open] =(unsigned long*) our_sys_open;
	protect_memory();
	/* 
	 * To get the address of the function for system
	 * call foo, go to sys_call_table[__NR_foo]. 
	 */

	printk(KERN_INFO "Spying on UID:");

	return 0;
}

/* 
 * Cleanup - unregister the appropriate file from /proc 
 */
void cleanup_module()
{
	/* 
	 * Return the system call back to normal 
	 */
	//if (sys_call_table[__NR_open] != our_sys_open) {
	//	printk(KERN_ALERT "Somebody else also played with the ");
	//	printk(KERN_ALERT "open system call\n");
	//	printk(KERN_ALERT "The system may be left in ");
	//	printk(KERN_ALERT "an unstable state.\n");
	//}
	unprotect_memory();
	sys_call_table[__NR_open] = (unsigned long*)original_call;
	protect_memory();
}
