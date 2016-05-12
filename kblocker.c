#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/syscalls.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/version.h>
#include<linux/slab.h>
#include <linux/times.h>
#include <linux/timekeeping.h>
#include <linux/rtc.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/unistd.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
//#include <asm-generic/uaccess.h>

#define CR0_WP 0x00010000   // Write  Protect Bit (CR0:16)
#define MAX_HISTORY 10  // Maximum history list size
#define MAX_HISTORY_LINE (PATH_MAX*3 + 100) //The maximum message line contains 3 file path + extra const words

int is_exe_mon_enabled = 1;
int is_script_mon_enabled = 1;
int is_exe_blocking_enabled = 1;
int is_script_blocking_enabled = 1;

static char *msg = NULL;
//
//extern struct history_node file_mon_history;    // History of filemon events
//extern struct history_node net_mon_history;     // History of netmon events
//extern struct history_node mount_mon_history;   // History of mountmon events

static char msg_read[400] = "";
static char first_must_line[] = "KBlocker - Last Events:\n";
static char second_must_line[] = "KBlocker Current Configuration:\n";
static char third_must_line[] = "SHA256 hashes to block (Executables):\n";
static char fourth_must_line[] = "SHA256 hashes to block (Python Scripts):\n";
static ssize_t len_check = 1;

// Node in the list of messages
struct history_node {
    struct list_head node;
    char msg[MAX_HISTORY_LINE];
    long time_in_sec;
};

MODULE_LICENSE("GPL");

void **syscall_table;

unsigned long **find_sys_call_table(void);
int (*orig_sys_execve)(const char __user *filename, const char __user *const __user *argv,
                        const char __user *const __user *envp);

unsigned long **find_sys_call_table()
{
    unsigned long ptr;
    unsigned long *p;
    for (ptr = (unsigned long) sys_close; ptr < (unsigned long) &loops_per_jiffy; ptr += sizeof(void *))
    {
        p = (unsigned long *) ptr;
        if (p[__NR_close] == (unsigned long) sys_close)
        {
            return (unsigned long **) p;
        }
    }
    return NULL;
}


int my_sys_execve(const char __user *filename, const char __user *const __user *argv,
                   const char __user *const __user *envp)
{
    struct timeval time;
    unsigned long local_time;
    struct rtc_time tm;
    // Get current time
    do_gettimeofday(&time);
    local_time = (u32)(time.tv_sec - (sys_tz.tz_minuteswest * 60));
    rtc_time_to_tm(local_time, &tm);
    if (is_script_mon_enabled && strlen(filename) > 6 && !strcmp(filename + strlen(filename) - 6, "python"))
    {
        // Write to dmesg
        printk(KERN_INFO
        "%02d/%02d/%04d %02d:%02d:%02d, SCRIPT: %s was loaded under python with pid %i\n",
        tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec,
        argv[1], current->pid);
    }
    else if(is_exe_mon_enabled)
    {
        // Write to dmesg
        printk(KERN_INFO
        "%02d/%02d/%04d %02d:%02d:%02d, EXECUTABLE: %s was loaded with pid %i\n",
        tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec,
        filename, current->pid);
    }
    return orig_sys_execve(filename, argv, envp);
}


/**
* This function is called then the kmonitorproc file is read
*
*/
ssize_t kblocker_proc_read(struct file *sp_file, char __user *buf, size_t size, loff_t *offset)
{
    int msg_len = 0, i;
    long max_time;
    struct history_node *net_line = NULL, *mount_line = NULL, *file_line = NULL, *max_line = NULL;
    struct list_head *net_pos = NULL, *mount_pos = NULL, *file_pos = NULL;
    size_t curr_size = strlen(first_must_line)+1;
    size_t curr_tmp_size = 0;
    char *tmp_msg = NULL, *tmp_msg2 = NULL;
    if(len_check)
        len_check = 0;
    else
    {
        len_check = 1;
        return 0;
    }

    // Start building KMonitor report
    msg = (char *)kmalloc(sizeof(char) * size, GFP_KERNEL);
    if(unlikely(!msg))
    {
        printk(KERN_ERR "Not enough memory for message! \n");
        return -1;
    }
    strcpy(msg, first_must_line);

//    lock_all_history();
//    mount_pos = mount_mon_history.node.next;
//    net_pos = net_mon_history.node.next;
//    file_pos = file_mon_history.node.next;
//    // Init lines with first line
//    if(net_pos != &net_mon_history.node)
//    {
//    net_line = list_entry(net_pos, struct history_node, node);
//    }
//    if(mount_pos != &mount_mon_history.node)
//    {
//    mount_line = list_entry(mount_pos, struct history_node, node);
//    }
//    if(file_pos != &file_mon_history.node)
//    {
//    file_line = list_entry(file_pos, struct history_node, node);
//    }
//
//    // Find last 10 history messages.
//    for(i = 0; i < MAX_HISTORY && (net_pos != &net_mon_history.node || mount_pos != &mount_mon_history.node
//    || file_pos != &file_mon_history.node); i++)
//    {
//    // Find maximum time between 3 history sorted lists
//    max_time = -1;
//    if(net_line != NULL && net_line->time_in_sec > max_time)
//    {
//    max_time = net_line->time_in_sec;
//    }
//    if(mount_line != NULL && mount_line->time_in_sec > max_time)
//    {
//    max_time = mount_line->time_in_sec;
//    }
//    if (file_line != NULL && file_line->time_in_sec > max_time)
//    {
//    max_time = file_line->time_in_sec;
//    }
//
//    // Get the message with the maximum time and advance to the next line
//    if(net_line != NULL && max_time == net_line->time_in_sec)
//    {
//    max_line = net_line;
//    net_pos = net_pos->next;
//    if(net_pos != &net_mon_history.node)
//    {
//    net_line = list_entry(net_pos, struct history_node, node);
//    }
//    else
//    {
//    net_line = NULL;
//    }
//    }
//    else if(mount_line != NULL && max_time == mount_line->time_in_sec)
//    {
//    max_line = mount_line;
//    mount_pos = mount_pos->next;
//    if(mount_pos != &mount_mon_history.node)
//    {
//    mount_line = list_entry(mount_pos, struct history_node, node);
//    }
//    else
//    {
//    mount_line = NULL;
//    }
//    }
//    else if(file_line != NULL && max_time == file_line->time_in_sec)
//    {
//    max_line = file_line;
//    file_pos = file_pos->next;
//    if(file_pos != &file_mon_history.node)
//    {
//    file_line = list_entry(file_pos, struct history_node, node);
//    }
//    else
//    {
//    file_line = NULL;
//    }
//    }
//
//    curr_tmp_size += strlen(max_line->msg)+1;
//    tmp_msg = (char *)kmalloc((size_t)(sizeof(char)*curr_tmp_size), GFP_KERNEL);
//    if(unlikely(!tmp_msg))
//    {
//    printk(KERN_ERR "Not enough memory for message! \n");
//    unlock_all_history();
//    return -1;
//    }
//    // Some string manipulation to insert the message to the start of the report
//    strcpy(tmp_msg, max_line->msg);
//    if(tmp_msg2)
//    {
//    strcat(tmp_msg, tmp_msg2);
//    kfree(tmp_msg2);
//    }
//    tmp_msg2 = tmp_msg;
//    }
//    unlock_all_history();
//    // Add last 10 history messages to the KMonitor report
//    if(tmp_msg2)
//    {
//    curr_size += strlen(tmp_msg2)+1;
//    msg = (char *)krealloc(msg, (size_t)(sizeof(char)*curr_size), GFP_KERNEL);
//    if(unlikely(!msg))
//    {
//    printk(KERN_ERR "Not enough memory for message! \n");
//    return -1;
//    }
//    strcat(msg, tmp_msg2);
//    }
    // Add configuration info to the KMonitor report.
    strcpy(msg_read, second_must_line);
//    lock_all_enabled();
    if(is_exe_mon_enabled)
        strcat(msg_read, "Executable Monitoring Mode - Enabled\n");
    else
        strcat(msg_read, "Executable Monitoring Mode - Disabled\n");
    if(is_script_mon_enabled)
        strcat(msg_read, "Python Scripts Monitoring Mode - Enabled\n");
    else
        strcat(msg_read, "Python Scripts Monitoring Mode - Disabled\n");
    if(is_exe_blocking_enabled)
        strcat(msg_read, "Executable Blocking Mode - Enabled\n");
    else
        strcat(msg_read, "Executable Blocking Mode - Disabled\n");
    if(is_script_blocking_enabled)
        strcat(msg_read, "Python Scripts Blocking Mode - Enabled\n");
    else
        strcat(msg_read, "Python Scripts Blocking Mode - Disabled\n");
//    unlock_all_enabled();
    curr_size += strlen(msg_read)+1;
    msg = (char *)krealloc(msg, (size_t)(sizeof(char)*curr_size), GFP_KERNEL);
    if(unlikely(!msg))
    {
        printk(KERN_ERR "Not enough memory for message! \n");
        return -1;
    }
    strcat(msg, msg_read);
    strcat(msg, third_must_line);
    strcat(msg, fourth_must_line);
    msg_len = strlen(msg) + 1;
    copy_to_user(buf, msg, msg_len);
    kfree(msg);
    return msg_len;
}

/**
* This function is called then the kmonitorproc file is written
*
*/
ssize_t kblocker_proc_write(struct file *sp_file, const char __user *buf, size_t size, loff_t *offset)
{
    msg = (char *)kmalloc(size, GFP_KERNEL);
    if(unlikely(!msg))
    {
        printk(KERN_ERR "Not enough memory for message! \n");
        return -1;
    }
    copy_from_user(msg, buf, size);
    // Enable or Disable some monitor
    if(strstr(msg, "ExecMon 0")){
//        mutex_lock_killable(&network_enabled_mutex);
        is_exe_mon_enabled = 0;
//        mutex_unlock(&network_enabled_mutex);
    }
    else if(strstr(msg, "ExecMon 1")){
//    mutex_lock_killable(&network_enabled_mutex);
        is_exe_mon_enabled = 1;
//    mutex_unlock(&network_enabled_mutex);
    }
    else if(strstr(msg, "ScriptMon 0")){
//    mutex_lock_killable(&file_enabled_mutex);
        is_script_mon_enabled = 0;
//    mutex_unlock(&file_enabled_mutex);
    }
    else if(strstr(msg, "ScriptMon 1")){
//    mutex_lock_killable(&file_enabled_mutex);
        is_script_mon_enabled = 1;
//    mutex_unlock(&file_enabled_mutex);
    }
    else if(strstr(msg, "ExecBlock 0")){
//    mutex_lock_killable(&mount_enabled_mutex);
        is_exe_blocking_enabled = 0;
//    mutex_unlock(&mount_enabled_mutex);
    }
    else if(strstr(msg, "ExecBlock 1")){
//    mutex_lock_killable(&mount_enabled_mutex);
        is_exe_blocking_enabled = 1;
//    mutex_unlock(&mount_enabled_mutex);
    }
    else if(strstr(msg, "ScriptBlock 0")){
    //    mutex_lock_killable(&mount_enabled_mutex);
        is_script_blocking_enabled = 0;
    //    mutex_unlock(&mount_enabled_mutex);
    }
    else if(strstr(msg, "ScriptBlock 1")){
    //    mutex_lock_killable(&mount_enabled_mutex);
        is_script_blocking_enabled = 1;
    //    mutex_unlock(&mount_enabled_mutex);
    }
    kfree(msg);
    return size;
}


// Point proc read and write to our functions
struct file_operations fops = {
        .read = kblocker_proc_read,
        .write = kblocker_proc_write,
};




// Init module
static int __init init_kblockerproc (void)
{
    char *ptr = NULL;
    unsigned long cr0;
    printk(KERN_DEBUG "Let's do some magic!\n");

    syscall_table = (void **) find_sys_call_table();

    if (!syscall_table) {
        printk(KERN_DEBUG "ERROR: Cannot find the system call table address.\n");
        return -1;
    }

    printk(KERN_DEBUG "Found the sys_call_table at %16lx.\n", (unsigned long) syscall_table);

    cr0 = read_cr0();
    write_cr0(cr0 & ~CR0_WP);

    printk(KERN_DEBUG "Read only disabled. Proceeding...\n");

    /* syscall_table[__NR_execve] points to stub_execve.
       Search for call instruction opcode (0xE8) inside stub_execve */
    ptr = memchr(syscall_table[__NR_execve], 0xE8, 200);
    if (!ptr)
    {
        printk("Bad stub_execve\n");
        return -1;
    }
    ptr++; // Jump over 0xE8 to the sys_execve addr
    orig_sys_execve = (void*) ptr + *(int32_t*) ptr + 4; // Save original sys_execve addr that stub_execve called
    *(int32_t*) ptr = (char*) my_sys_execve - ptr - 4;   // Change inside stub_execve to call to my_sys_execve addr

    write_cr0(cr0);
    printk(KERN_INFO "Started KBlocker\n");
    if (!proc_create("KBlocker",0666,NULL,&fops))
    {
        printk(KERN_INFO "ERROR! proc_create\n");
        remove_proc_entry("KBlocker",NULL);
        return -1;
    }
    return 0;
}

// Release module
static void __exit exit_kblockerproc(void)
{
    char *ptr = NULL;
    unsigned long cr0;
    cr0 = read_cr0();
    write_cr0(cr0 & ~CR0_WP);
    ptr = memchr(syscall_table[__NR_execve], 0xE8, 200);
    if (!ptr++) printk("Bad stub_execve\n");
    *(int32_t*) ptr = (char*) orig_sys_execve - ptr - 4;
    write_cr0(cr0);

    remove_proc_entry("KBlocker", NULL);
    printk(KERN_INFO "Exit KBlocker\n");
}

module_init(init_kblockerproc);
module_exit(exit_kblockerproc);

