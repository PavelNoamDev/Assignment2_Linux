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
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
//#include <asm-generic/uaccess.h>

#define NETLINK_USER 31
#define CR0_WP 0x00010000   // Write  Protect Bit (CR0:16)
#define MAX_HISTORY 10  // Maximum history list size
#define MAX_HISTORY_LINE (PATH_MAX*3 + 100) //The maximum message line contains 3 file path + extra const words

int curr_num_of_history_lines = 0;

struct history_node kblocker_history;  // History of events

int is_exe_mon_enabled = 1;
int is_script_mon_enabled = 1;
int is_exe_blocking_enabled = 1;
int is_script_blocking_enabled = 1;

static char *msg = NULL;
struct sock *nl_sk = NULL; // Netlink socket
int user_pid = -1; // User mode process pid

static char msg_read[400] = "";
static char first_must_line[] = "KBlocker - Last Events:\n";
static char second_must_line[] = "KBlocker Current Configuration:\n";
static char third_must_line[] = "SHA256 hashes to block (Executables):\n";
static char fourth_must_line[] = "SHA256 hashes to block (Python Scripts):\n";
static ssize_t len_check = 1;

//int have_responce = 0;
//DECLARE_WAIT_QUEUE_HEAD(responce_waitqueue);     // Waitqueue for wait responce.

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
    struct history_node *line_to_add = NULL, *last_history_node = NULL;
    struct timeval time;
    unsigned long local_time;
    struct rtc_time tm;
    int is_kblocker_user = 0;
    struct nlmsghdr *nlh;
    struct sk_buff *skb_out;
    int msg_size;
    int res;
    // Get current time
    do_gettimeofday(&time);
    local_time = (u32)(time.tv_sec - (sys_tz.tz_minuteswest * 60));
    rtc_time_to_tm(local_time, &tm);

    if (strlen(filename) > 10 && !strcmp(filename + strlen(filename) - 10, "KBlockerUM")){
        user_pid = current->pid;
        printk(KERN_INFO "KBlockerUM with pid: %i\n", user_pid);
        is_kblocker_user = 1;
    }

    if(!is_kblocker_user && (is_script_blocking_enabled || is_exe_blocking_enabled)){
        msg_size = strlen(filename);
        skb_out = nlmsg_new(msg_size, 0);
        if (!skb_out) {
            printk(KERN_ERR "Failed to allocate new skb\n");
            return -1;
        }

        nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
        NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
        strncpy(nlmsg_data(nlh), msg, msg_size);
//        have_responce = 0;
        res = nlmsg_unicast(nl_sk, skb_out, user_pid);
        if (res < 0)
            printk(KERN_INFO "Error while sending bak to user\n");
//        wait_event(responce_waitqueue, have_responce); //wait until responce is received
    }

    if (is_script_mon_enabled && strlen(filename) > 6 && !strcmp(filename + strlen(filename) - 6, "python") && argv[1])
    {
        // Write to dmesg
        printk(KERN_INFO
        "%02d/%02d/%04d %02d:%02d:%02d, SCRIPT: %s was loaded under python with pid %i\n",
        tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec,
        argv[1], current->pid);

        // Save to history
        line_to_add = (struct history_node *)kmalloc(sizeof(struct history_node), GFP_KERNEL);
        if(unlikely(!line_to_add))
        {
            printk(KERN_ERR "Not enough memory for history_node!\n");
            return -1;
        }
        snprintf(line_to_add->msg, MAX_HISTORY_LINE,
        "%02d/%02d/%04d %02d:%02d:%02d, SCRIPT: %s was loaded under python with pid %i\n",
        tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec,
        argv[1], current->pid);
        line_to_add->time_in_sec = (u32)time.tv_sec;

        list_add(&(line_to_add->node), &(kblocker_history.node));
        curr_num_of_history_lines++;
    }
    else if(is_exe_mon_enabled)
    {
        // Write to dmesg
        printk(KERN_INFO
        "%02d/%02d/%04d %02d:%02d:%02d, EXECUTABLE: %s was loaded with pid %i\n",
        tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec,
        filename, current->pid);
        // Save to history
        line_to_add = (struct history_node *)kmalloc(sizeof(struct history_node), GFP_KERNEL);
        if(unlikely(!line_to_add))
        {
            printk(KERN_ERR "Not enough memory for history_node!\n");
            return -1;
        }
        snprintf(line_to_add->msg, MAX_HISTORY_LINE,
        "%02d/%02d/%04d %02d:%02d:%02d, EXECUTABLE: %s was loaded with pid %i\n",
        tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec,
        filename, current->pid);
        line_to_add->time_in_sec = (u32)time.tv_sec;

        list_add(&(line_to_add->node), &(kblocker_history.node));
        curr_num_of_history_lines++;
    }

    // If more then 10 lines delete the oldest one
    if(curr_num_of_history_lines > MAX_HISTORY)
    {
        last_history_node = list_last_entry(&(kblocker_history.node), struct history_node, node);
        list_del(&(last_history_node->node));
        kfree(last_history_node);
        curr_num_of_history_lines--;
    }

    return orig_sys_execve(filename, argv, envp);
}


/**
* This function is called then the kblockerproc file is read
*
*/
ssize_t kblocker_proc_read(struct file *sp_file, char __user *buf, size_t size, loff_t *offset)
{
    int msg_len = 0, i;
    struct history_node *history_line = NULL;
    struct list_head *history_pos = NULL;
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

    // Start building KBlocker report
    msg = (char *)kmalloc(sizeof(char) * size, GFP_KERNEL);
    if(unlikely(!msg))
    {
        printk(KERN_ERR "Not enough memory for message! \n");
        return -1;
    }
    strcpy(msg, first_must_line);

    history_pos = kblocker_history.node.next;
    // Init line with first line
    if(history_pos  != &kblocker_history.node)
        history_line = list_entry(history_pos, struct history_node, node);

    for(i = 0; i < MAX_HISTORY && history_pos != &kblocker_history.node; i++)
    {
        curr_tmp_size += strlen(history_line->msg)+1;
        tmp_msg = (char *)kmalloc((size_t)(sizeof(char)*curr_tmp_size), GFP_KERNEL);
        if(unlikely(!tmp_msg))
        {
            printk(KERN_ERR "Not enough memory for message! \n");
            return -1;
        }
        // Some string manipulation to insert the message to the start of the report
        strcpy(tmp_msg, history_line->msg);
        if(tmp_msg2)
        {
            strcat(tmp_msg, tmp_msg2);
            kfree(tmp_msg2);
        }
        tmp_msg2 = tmp_msg;
        history_pos = history_pos->next;
        if(history_pos != &kblocker_history.node)
            history_line = list_entry(history_pos, struct history_node, node);
        else
            history_line = NULL;
    }

    // Add last 10 history messages to the KBlocker report
    if(tmp_msg2)
    {
        curr_size += strlen(tmp_msg2)+1;
        msg = (char *)krealloc(msg, (size_t)(sizeof(char)*curr_size), GFP_KERNEL);
        if(unlikely(!msg))
        {
            printk(KERN_ERR "Not enough memory for message! \n");
            return -1;
        }
        strcat(msg, tmp_msg2);
    }
    // Add configuration info to the KMonitor report.
    strcpy(msg_read, second_must_line);
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
* This function is called then the kblockerproc file is written
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
        is_exe_mon_enabled = 0;
    }
    else if(strstr(msg, "ExecMon 1")){
        is_exe_mon_enabled = 1;
    }
    else if(strstr(msg, "ScriptMon 0")){
        is_script_mon_enabled = 0;
    }
    else if(strstr(msg, "ScriptMon 1")){
        is_script_mon_enabled = 1;
    }
    else if(strstr(msg, "ExecBlock 0")){
        is_exe_blocking_enabled = 0;
    }
    else if(strstr(msg, "ExecBlock 1")){
        is_exe_blocking_enabled = 1;
    }
    else if(strstr(msg, "ScriptBlock 0")){
        is_script_blocking_enabled = 0;
    }
    else if(strstr(msg, "ScriptBlock 1")){
        is_script_blocking_enabled = 1;
    }
    kfree(msg);
    return size;
}


static void nl_recv_msg(struct sk_buff *skb) {
    struct nlmsghdr *nlh;
    printk(KERN_INFO "Entering: %s\n", __FUNCTION__);

    nlh = (struct nlmsghdr *)skb->data;
    printk(KERN_INFO "Netlink received msg payload:%s\n", (char *)nlmsg_data(nlh));
    user_pid = nlh->nlmsg_pid; /*pid of sending process */
//    have_responce = 1;
//    wake_up_all(&responce_waitqueue);
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
    struct netlink_kernel_cfg cfg = {
            .input = nl_recv_msg,
    };
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
    ptr++; // Jump over 0xE8 to the sys_execve address
    orig_sys_execve = (void*) ptr + *(int32_t*) ptr + 4; // Save original sys_execve address that stub_execve called
    *(int32_t*) ptr = (char*) my_sys_execve - ptr - 4;   // Change inside stub_execve to call to my_sys_execve address

    write_cr0(cr0);

    printk(KERN_INFO "Started KBlocker\n");
    if (!proc_create("KBlocker",0666,NULL,&fops))
    {
        printk(KERN_INFO "ERROR! proc_create\n");
        remove_proc_entry("KBlocker",NULL);
        return -1;
    }

    // Init seen history list
    INIT_LIST_HEAD(&kblocker_history.node);

    // Create netlink socket
    nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
    if (!nl_sk) {
        printk(KERN_ALERT "Error creating socket.\n");
        return -10;
    }


    return 0;
}

// Release module
static void __exit exit_kblockerproc(void)
{
    char *ptr = NULL;
    unsigned long cr0;
    struct history_node *curr_his_node = NULL;
    struct list_head *tmp_node = NULL, *pos = NULL;

    cr0 = read_cr0();
    write_cr0(cr0 & ~CR0_WP);
    ptr = memchr(syscall_table[__NR_execve], 0xE8, 200);
    if (!ptr++) printk("Bad stub_execve\n");
    *(int32_t*) ptr = (char*) orig_sys_execve - ptr - 4;
    write_cr0(cr0);

    // Free memory of history
    list_for_each_safe(pos, tmp_node, &kblocker_history.node)
    {
        curr_his_node = list_entry(pos, struct history_node, node);
        printk(KERN_DEBUG "Freeing node with msg: %s \n", curr_his_node->msg);
        kfree(curr_his_node);
    }

    remove_proc_entry("KBlocker", NULL);
    netlink_kernel_release(nl_sk); // Close Netlink socket
    printk(KERN_INFO "Exit KBlocker\n");


}

module_init(init_kblockerproc);
module_exit(exit_kblockerproc);

