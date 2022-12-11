#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <asm/unistd.h>

void** p_table;
void* old_mkdir;

static void disable_write_protect(void) {
    unsigned long cr0 = read_cr0();
    clear_bit(16, &cr0);
    write_cr0(cr0);
}

static void enable_write_protect(void) {
    unsigned long cr0 = read_cr0();
    set_bit(16, &cr0);
    write_cr0(cr0);
}

static int new_mkdir(const char *pathname, mode_t mode) {
    int (*ori_mkdir)(const char*, mode_t) = old_mkdir;
    printk("Mkdir: [path]%s [mode]%d\n", pathname, mode);
    return ori_mkdir(pathname, mode);
}

static int init_hook(void) {
    p_table = \
        (void **)kallsyms_lookup_name("sys_call_table");
    printk("Init hook:\n");
    old_mkdir = p_table[__NR_mkdir];
    disable_write_protect();
    p_table[__NR_mkdir] = new_mkdir;
    enable_write_protect();
    printk("Mkdir: %p => %p\n", old_mkdir, new_mkdir);
    return 0;
}

static void exit_hook(void) {
    disable_write_protect();
    p_table[__NR_mkdir] = old_mkdir;
    enable_write_protect();
    return;
}

MODULE_LICENSE("GPL");
module_init(init_hook);
module_exit(exit_hook);