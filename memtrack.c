#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/kallsyms.h>
#include <linux/hashtable.h>
#include <linux/fs.h>
#include <linux/kprobes.h>

#define HASH_BUCKETS 256
#define LOG_FILE_PATH "/var/log/user_memory_leaks.log"

// struct for individual memory allocations
struct mem_alloc_info {
    void *address;       
    size_t size;         
    struct list_head list;
};

//struct for all memory allocations of a process....
struct process_mem_info {
    pid_t pid;                     
    struct list_head alloc_list;   
    struct mutex lock;             
    struct hlist_node node;        
};

// Hash table to store tracked processes
static DEFINE_HASHTABLE(process_table, 8);
static DEFINE_MUTEX(process_table_lock);


static void log_to_file(const char *message) {
    struct file *f;
    loff_t pos;
    f = filp_open(LOG_FILE_PATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (IS_ERR(f)) {
        pr_err("Failed to open log file: %s\n", LOG_FILE_PATH);
        return;
    }
    pos = 0;
    kernel_write(f, message, strlen(message), &pos);
    filp_close(f, NULL);
}


SYSCALL_DEFINE4(track_user_memory, pid_t, pid, int, operation, void *, address, size_t, size) {
    struct process_mem_info *pinfo;
    struct mem_alloc_info *ainfo, *tmp;
    char log_message[256];

    if (pid <= 0)
        return -EINVAL;

    mutex_lock(&process_table_lock);

   
    hash_for_each_possible(process_table, pinfo, node, pid) {
        if (pinfo->pid == pid) {
            switch (operation) {
                case 0: // Start tracking
                    snprintf(log_message, sizeof(log_message),
                             "Tracking already started for PID %d\n", pid);
                    log_to_file(log_message);
                    mutex_unlock(&process_table_lock);
                    return 0;

                case 1: // Track allocation
                    if (address == NULL || size == 0) {
                        mutex_unlock(&process_table_lock);
                        return -EINVAL;
                    }
                    mutex_lock(&pinfo->lock);
                    ainfo = kmalloc(sizeof(*ainfo), GFP_KERNEL);
                    if (!ainfo) {
                        mutex_unlock(&pinfo->lock);
                        mutex_unlock(&process_table_lock);
                        return -ENOMEM;
                    }
                    ainfo->address = address;
                    ainfo->size = size;
                    list_add(&ainfo->list, &pinfo->alloc_list);
                    snprintf(log_message, sizeof(log_message),
                             "PID %d allocated memory: Address=%p, Size=%zu bytes\n",
                             pid, address, size);
                    log_to_file(log_message);
                    mutex_unlock(&pinfo->lock);
                    mutex_unlock(&process_table_lock);
                    return 0;

                case 2: // Track deallocation
                    if (address == NULL) {
                        mutex_unlock(&process_table_lock);
                        return -EINVAL;
                    }
                    mutex_lock(&pinfo->lock);
                    list_for_each_entry_safe(ainfo, tmp, &pinfo->alloc_list, list) {
                        if (ainfo->address == address) {
                            snprintf(log_message, sizeof(log_message),
                                     "PID %d freed memory: Address=%p, Size=%zu bytes\n",
                                     pid, address, ainfo->size);
                            log_to_file(log_message);
                            list_del(&ainfo->list);
                            kfree(ainfo);
                            mutex_unlock(&pinfo->lock);
                            mutex_unlock(&process_table_lock);
                            return 0;
                        }
                    }
                    mutex_unlock(&pinfo->lock);
                    mutex_unlock(&process_table_lock);
                    return -ESRCH;

                default:
                    mutex_unlock(&process_table_lock);
                    return -EINVAL;
            }
        }
    }

   
    if (operation == 0) {
        struct task_struct *task;
        rcu_read_lock();
        task = find_task_by_vpid(pid);
        rcu_read_unlock();
        if (!task) {
            mutex_unlock(&process_table_lock);
            return -ESRCH;
        }

        pinfo = kmalloc(sizeof(*pinfo), GFP_KERNEL);
        if (!pinfo) {
            mutex_unlock(&process_table_lock);
            return -ENOMEM;
        }
        INIT_LIST_HEAD(&pinfo->alloc_list);
        mutex_init(&pinfo->lock);
        pinfo->pid = pid;
        hash_add(process_table, &pinfo->node, pid);
        snprintf(log_message, sizeof(log_message),
                 "Started tracking user memory allocations for PID %d\n", pid);
        log_to_file(log_message);
        mutex_unlock(&process_table_lock);
        return 0;
    }

    mutex_unlock(&process_table_lock);
    return -ESRCH;
}

static struct kprobe kp_do_exit = {
    .symbol_name = "do_exit"
};

static int do_exit_pre_handler(struct kprobe *p, struct pt_regs *regs) {
    struct task_struct *task = current;
    struct process_mem_info *pinfo;
    struct mem_alloc_info *ainfo, *tmp;
    size_t total_leaked = 0;
    int leaked_count = 0;
    char log_message[256];

    mutex_lock(&process_table_lock);

=    hash_for_each_possible(process_table, pinfo, node, task->pid) {
        if (pinfo->pid == task->pid) {
            mutex_lock(&pinfo->lock);

            list_for_each_entry_safe(ainfo, tmp, &pinfo->alloc_list, list) {
                total_leaked += ainfo->size;
                leaked_count++;
                snprintf(log_message, sizeof(log_message),
                         "Leaked memory: Address=%p, Size=%zu bytes\n",
                         ainfo->address, ainfo->size);
                log_to_file(log_message);

                list_del(&ainfo->list);
                kfree(ainfo);
            }

            mutex_unlock(&pinfo->lock);

            if (total_leaked > 0) {
                snprintf(log_message, sizeof(log_message),
                         "Process %d exited with %zu bytes of leaked memory (%d allocations)\n",
                         task->pid, total_leaked, leaked_count);
                log_to_file(log_message);
            } else {
                snprintf(log_message, sizeof(log_message),
                         "Process %d exited with no memory leaks\n", task->pid);
                log_to_file(log_message);
            }

            // Remove the process from the hash table
            hash_del(&pinfo->node);
            kfree(pinfo);
            break; 
        }
    }

    mutex_unlock(&process_table_lock);
    return 0;
}



static int __init memory_tracker_setup(void) {
    pr_info("User memory tracker syscall initialized\n");

    struct file *f;
    loff_t pos;
    f = filp_open(LOG_FILE_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (IS_ERR(f)) {
        pr_err("Failed to create log file: %s\n", LOG_FILE_PATH);
    } else {
        pos = 0;
        filp_close(f, NULL);
    }

    
    int ret = register_kprobe(&kp_do_exit);
    if (ret < 0) {
        pr_err("Failed to register kprobe for do_exit, error %d\n", ret);
        return ret;
    }

    return 0;
}


early_initcall(memory_tracker_setup);
