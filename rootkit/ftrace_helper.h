#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/kprobes.h>

#define HOOK(x, y, z) { .name = (x), .hooked = (y), .original = (z) }

/// Describes a hook we are trying to add
/// Only the first 3 fields are to be used by the user
struct ftrace_hook {
	const char *name;
	void *hooked;
	void *original;

	unsigned long address;
	struct ftrace_ops ops;
};

/// With kernel version 5.7, kallsyms_lookup_name() was removed from the
/// exported kernel functions. This makes it harder to resolve a symbol
/// name to a memory address. This can be solved by declaring a kprobe struct
/// with the .symbol_name set to the symbol we are trying to resolve. After
/// registering it, the .addr field will contain the address we are looking for.
static unsigned long lookup_name(const char *name) {
	struct kprobe kp = {
		.symbol_name = name
	};
	unsigned long addr;

	if (register_kprobe(&kp) < 0) { return 0; }
	addr = (unsigned long) kp.addr;
	unregister_kprobe(&kp);
	return addr;
}

/// Find address of given syscall
static int fh_resolve_hook_address(struct ftrace_hook *hook) {
	hook->address = lookup_name(hook->name);
    *((unsigned long*) hook->original) = hook->address;

	return 0;
}

/// This callback makes sure rip points to our hook when a hooked syscall is used
static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
		struct ftrace_ops *ops, struct ftrace_regs *fregs) {
	struct pt_regs *regs = ftrace_get_regs(fregs);
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

    if (!within_module(parent_ip, THIS_MODULE)) regs->ip = (unsigned long)hook->hooked;
}

/// Register and enable a hook
int fh_install_hook(struct ftrace_hook *hook) {

	if (fh_resolve_hook_address(hook)) { return -1; }

    // anti-recursion measures when hooking rip
	hook->ops.func = fh_ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
	                | FTRACE_OPS_FL_RECURSION
	                | FTRACE_OPS_FL_IPMODIFY;

	if (ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0)) { return -1; }
	if (register_ftrace_function(&hook->ops)) { return -1; }

	return 0;
}

/// Disable and remove `count` hooks from the `hooks` array
void fh_remove_hooks(struct ftrace_hook *hooks, size_t count) {
    size_t i;
	for (i = 0; i < count; i++) {
        unregister_ftrace_function(&hooks[i].ops);
        ftrace_set_filter_ip(&hooks[i].ops, hooks[i].address, 1, 0);
    }
}

/// Register `count` hooks using the `hooks` array
int fh_install_hooks(struct ftrace_hook *hooks, size_t count) {
	size_t i;

	for (i = 0; i < count; i++) {
		if (fh_install_hook(&hooks[i])) {
		    goto error;
        }
	}

	return 0;

error:
    fh_remove_hooks(hooks, i);
	return -1;
}

