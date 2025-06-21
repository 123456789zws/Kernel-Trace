#include <log.h>
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/cred.h>
#include <taskext.h>
#include <linux/printk.h>
#include <linux/uaccess.h>
#include <asm/current.h>
#include <linux/string.h>
#include <syscall.h>
#include <asm/current.h>
#include "kernel_trace.h"

KPM_NAME("kernel_trace");
KPM_VERSION("2.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Test");
KPM_DESCRIPTION("use uprobe trace some fun in kpm");

pid_t (*mtask_pid_nr_ns)(struct task_struct *task, enum pid_type type, struct pid_namespace *ns) = 0;
int (*uprobe_register)(struct inode *inode, loff_t offset, struct uprobe_consumer *uc) = 0;
void (*uprobe_unregister)(struct inode *inode, loff_t offset, struct uprobe_consumer *uc) = 0;
int (*kern_path)(const char *name, unsigned int flags, struct path *path) = 0;
struct inode *(*igrab)(struct inode *inode) = 0;
void (*path_put)(const struct path *path) = 0;
void (*rcu_read_unlock)(void) = 0;
int (*trace_printk)(unsigned long ip, const char *fmt, ...) = 0;


char file_name[MAX_PATH_LEN];
uid_t target_uid = -1;
unsigned long fun_offsets[MAX_HOOK_NUM];
int hook_num = 0;
struct rb_root fun_info_tree = RB_ROOT;
static struct inode *inode;
unsigned long module_base = 0;
static struct uprobe_consumer trace_uc;

void before_mincore(hook_fargs3_t *args, void *udata){
    int trace_flag = (int)syscall_argn(args, 1);
    if(trace_flag<TRACE_FLAG || trace_flag>TRACE_FLAG+CLEAR_UPROBE){
        return;
    }

    int trace_info = trace_flag-TRACE_FLAG;
    if(trace_info==SET_FUN_INFO){
        if(unlikely(hook_num==MAX_HOOK_NUM)){
            logke("+Test-Log+ MAX_HOOK_NUM:%d\n",MAX_HOOK_NUM);
            goto error_out;
        }

        if(!module_base || strlen(file_name)==0 || target_uid==-1){
            logke("+Test-Log+ module_base or file_name or target_uid not set\n");
            goto error_out;
        }

        unsigned long fun_offset = (unsigned long)syscall_argn(args, 0);
        const char __user *tfun_name = (typeof(tfun_name))syscall_argn(args, 2);
        char fun_name[MAX_FUN_NAME];
        compat_strncpy_from_user(fun_name,tfun_name,sizeof(fun_name));
        int insert_ret = insert_key_value(&fun_info_tree,fun_offset,fun_name);
        if(insert_ret==-1){
            logke("+Test-Log+ same fun 0x%llx set uprobe\n",fun_offset);
            goto error_out;
        }
//        logkd("+Test-Log+ fun_name:%s,fun_offset:0x%llx\n",fun_name,fun_offset);
        int hret = uprobe_register(inode,fun_offset,&trace_uc);
        if(hret<0){
            logke("+Test-Log+ set uprobe error in 0x%llx\n",fun_offset);
            goto error_out;
        }

        fun_offsets[hook_num] = fun_offset;
        hook_num++;
        goto success_out;
    }

    if(trace_info==SET_MODULE_BASE){
        module_base = (unsigned long)syscall_argn(args, 0);
        logkd("+Test-Log+ set module_base:0x%llx\n",module_base);
        goto success_out;
    }

    if(trace_info==SET_TARGET_UID){
        target_uid = (uid_t)syscall_argn(args, 0);
        logkd("+Test-Log+ set target_uid:%d\n",target_uid);
        goto success_out;
    }

    if(trace_info==SET_TARGET_FILE){
        const char __user *filename = (typeof(filename))syscall_argn(args, 2);
        compat_strncpy_from_user(file_name,filename,sizeof(file_name));
        logkd("+Test-Log+ set target_file_name:%s\n",file_name);
        struct path path;
        int fret = kern_path(file_name, LOOKUP_FOLLOW, &path);
        if(fret<0){
            logke("+Test-Log+ error file path:%s\n",file_name);
            goto error_out;
        }
        inode = igrab(path.dentry->d_inode);
        path_put(&path);
        logkd("+Test-Log+ success set file inode\n");
        goto success_out;
    }

    if(trace_info==CLEAR_UPROBE){
        rcu_read_unlock();//解锁，不然内核会崩
        for (int i = 0; i < hook_num; ++i) {
            uprobe_unregister(inode,fun_offsets[i],&trace_uc);
        }
        hook_num = 0;
        destroy_entire_tree(&fun_info_tree);
        logkd("+Test-Log+ success clear all uprobes\n");
        goto success_out;
    }

error_out:
    args->ret = SET_TRACE_ERROR;
    args->skip_origin = 1;
    return;

success_out:
    args->ret = SET_TRACE_SUCCESS;
    args->skip_origin = 1;
    return;
}


static int trace_handler(struct uprobe_consumer *self, struct mpt_regs *regs){
    struct task_struct *task = current;
    struct cred* cred = *(struct cred**)((uintptr_t)task + task_struct_offset.cred_offset);
    uid_t uid = *(uid_t*)((uintptr_t)cred + cred_offset.uid_offset);
    struct my_key_value *tfun;
    unsigned long fun_offset;
    if(uid==target_uid){
        fun_offset = regs->pc-module_base;
        tfun = search_key_value(&fun_info_tree,fun_offset);
        if(tfun){
            goto target_out;
        }else{
            tfun = search_key_value(&fun_info_tree,fun_offset- 0x1000);
            if(likely(tfun)){
                goto target_out;
            }
        }
    }else{
        goto no_target_out;
    }
    
target_out:
//    logkd("+Test-Log+ fun_name:%s,fun_offset:0x%llx calling\n",tfun->value,fun_offset);
    int trace_printk_ret = trace_printk(_THIS_IP_,"+Test-Log+ fun_name:%s,fun_offset:0x%llx calling\n",tfun->value,fun_offset);
    if(unlikely(trace_printk_ret<0)){
        logke("+Test-Log+ trace_printk error\n");
    }
    return 0;
    
no_target_out:
    return 0;
}


static long kernel_trace_init(const char *args, const char *event, void *__user reserved)
{
    logkd("kpm kernel_trace init\n");
    mtask_pid_nr_ns = (typeof(mtask_pid_nr_ns))kallsyms_lookup_name("__task_pid_nr_ns");
    uprobe_register = (typeof(uprobe_register))kallsyms_lookup_name("uprobe_register");
    uprobe_unregister = (typeof(uprobe_unregister))kallsyms_lookup_name("uprobe_unregister");
    kern_path = (typeof(kern_path))kallsyms_lookup_name("kern_path");
    igrab = (typeof(igrab))kallsyms_lookup_name("igrab");
    path_put = (typeof(path_put))kallsyms_lookup_name("path_put");
    rcu_read_unlock = (typeof(rcu_read_unlock))kallsyms_lookup_name("rcu_read_unlock");


    rb_erase = (typeof(rb_erase))kallsyms_lookup_name("rb_erase");
    rb_insert_color = (typeof(rb_insert_color))kallsyms_lookup_name("rb_insert_color");
    rb_first = (typeof(rb_first))kallsyms_lookup_name("rb_first");
    kmalloc = (typeof(kmalloc))kallsyms_lookup_name("__kmalloc");
    kfree = (typeof(kfree))kallsyms_lookup_name("kfree");
    
    trace_printk = (typeof(trace_printk))kallsyms_lookup_name("__trace_printk");

    logkd("+Test-Log+ mtask_pid_nr_ns:%llx\n",mtask_pid_nr_ns);
    logkd("+Test-Log+ uprobe_register:%llx\n",uprobe_register);
    logkd("+Test-Log+ uprobe_unregister:%llx\n",uprobe_unregister);
    logkd("+Test-Log+ kern_path:%llx\n",kern_path);
    logkd("+Test-Log+ igrab:%llx\n",igrab);
    logkd("+Test-Log+ path_put:%llx\n",path_put);
    logkd("+Test-Log+ rcu_read_unlock:%llx\n",rcu_read_unlock);

    logkd("+Test-Log+ rb_erase:%llx\n",rb_erase);
    logkd("+Test-Log+ rb_insert_color:%llx\n",rb_insert_color);
    logkd("+Test-Log+ rb_first:%llx\n",rb_first);
    logkd("+Test-Log+ kmalloc:%llx\n",kmalloc);
    logkd("+Test-Log+ kfree:%llx\n",kfree);
    
    logkd("+Test-Log+ trace_printk:%llx\n",trace_printk);

    if(!(mtask_pid_nr_ns && uprobe_register && uprobe_unregister
    && kern_path && igrab && path_put && rcu_read_unlock
    && rb_erase && rb_insert_color && rb_first && trace_printk)){
        logke("+Test-Log+ can not find some fun addr\n");
        return -1;
    }

    trace_uc.handler = trace_handler;

    hook_err_t err = inline_hook_syscalln(__NR_mincore, 3, before_mincore, 0, 0);
    if(err){
        logke("+Test-Log+ hook __NR_mincore error\n");
        return -1;
    }


    logkd("+Test-Log+ success init\n");
    return 0;
}

static long kernel_trace_control0(const char *args, char *__user out_msg, int outlen)
{
    pr_info("kernel_trace control, args: %s\n", args);

    return 0;
}

static long kernel_trace_exit(void *__user reserved)
{
    inline_unhook_syscall(__NR_mincore, before_mincore, 0);
    rcu_read_unlock();//解锁，不然内核会崩
    for (int i = 0; i < hook_num; ++i) {
        uprobe_unregister(inode,fun_offsets[i],&trace_uc);
    }
    logkd("+Test-Log+ success clear all uprobes\n");
    destroy_entire_tree(&fun_info_tree);
    logkd("kpm kernel_trace  exit\n");
}

KPM_INIT(kernel_trace_init);
KPM_CTL0(kernel_trace_control0);
KPM_EXIT(kernel_trace_exit);