#include <asm/ptrace.h>
#include <linux/spinlock.h>
#include "uprobe_trace.h"
#include "mrbtree.h"

#define _THIS_IP_  ({ __label__ __here; __here: (unsigned long)&&__here; })
#define MAX_PATH_LEN 300
#define MAX_FUN_NAME 150
#define LOOKUP_FOLLOW		0x0001
#define HASH_LEN_DECLARE u32 hash; u32 len

struct inode;
struct mm_struct;
struct vfsmount;
struct seq_file;

struct hlist_bl_node {
    struct hlist_bl_node *next, **pprev;
 };


struct qstr {
    union {
        struct {
            HASH_LEN_DECLARE;
        };
        u64 hash_len;
    };
    const unsigned char *name;
};

struct dentry {
    /* RCU lookup touched fields */
    unsigned int d_flags;		/* protected by d_lock */
    spinlock_t d_seq;	/* per dentry seqlock */
    struct hlist_bl_node d_hash;	/* lookup hash list */
    struct dentry *d_parent;	/* parent directory */
    struct qstr d_name;
    struct inode *d_inode;
};

struct path {
    struct vfsmount *mnt;
    struct dentry *dentry;
} __randomize_layout;

enum uprobe_filter_ctx {
    UPROBE_FILTER_REGISTER,
    UPROBE_FILTER_UNREGISTER,
    UPROBE_FILTER_MMAP,
};

struct mpt_regs {
	union {
		struct user_pt_regs user_regs;
		struct {
			u64 regs[31];
			u64 sp;
			u64 pc;
			u64 pstate;
		};
	};
};

struct uprobe_consumer {
    int (*handler)(struct uprobe_consumer *self, struct mpt_regs *regs);
    int (*ret_handler)(struct uprobe_consumer *self,
                       unsigned long func,
                       struct mpt_regs *regs);
    bool (*filter)(struct uprobe_consumer *self,
                   enum uprobe_filter_ctx ctx,
                   struct mm_struct *mm);

    struct uprobe_consumer *next;
};

struct vm_area_struct {
    /* The first cache line has the info for VMA tree walking. */

    unsigned long vm_start;		/* Our start address within vm_mm. */
    unsigned long vm_end;
};

struct pid_namespace;
