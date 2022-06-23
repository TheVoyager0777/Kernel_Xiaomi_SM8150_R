/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_BINDER_INTERNAL_H
#define _LINUX_BINDER_INTERNAL_H

#include <linux/export.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/stddef.h>
#include <linux/types.h>
#include <linux/uidgid.h>
#include <uapi/linux/android/binderfs.h>
#include <uapi/linux/eventpoll.h>
#include "binder_alloc.h"
#include "binder_struct.h"

#define ida_alloc_max(a, b, c) ida_simple_get(a, 0, b + 1, c)
#define ida_free ida_remove

typedef unsigned int __poll_t;

struct binder_context {
	struct binder_node *binder_context_mgr_node;
	struct mutex context_mgr_node_lock;
	kuid_t binder_context_mgr_uid;
	const char *name;
};

/**
 * struct binder_device - information about a binder device node
 * @hlist:          list of binder devices (only used for devices requested via
 *                  CONFIG_ANDROID_BINDER_DEVICES)
 * @miscdev:        information about a binder character device node
 * @context:        binder context information
 * @binderfs_inode: This is the inode of the root dentry of the super block
 *                  belonging to a binderfs mount.
 */
struct binder_device {
	struct hlist_node hlist;
	struct miscdevice miscdev;
	struct binder_context context;
	struct inode *binderfs_inode;
	refcount_t ref;
};

/**
 * binderfs_mount_opts - mount options for binderfs
 * @max: maximum number of allocatable binderfs binder devices
 * @stats_mode: enable binder stats in binderfs.
 */
struct binderfs_mount_opts {
	int max;
	int stats_mode;
};

/**
 * binderfs_info - information about a binderfs mount
 * @ipc_ns:         The ipc namespace the binderfs mount belongs to.
 * @control_dentry: This records the dentry of this binderfs mount
 *                  binder-control device.
 * @root_uid:       uid that needs to be used when a new binder device is
 *                  created.
 * @root_gid:       gid that needs to be used when a new binder device is
 *                  created.
 * @mount_opts:     The mount options in use.
 * @device_count:   The current number of allocated binder devices.
 * @proc_log_dir:   Pointer to the directory dentry containing process-specific
 *                  logs.
 */
struct binderfs_info {
	struct ipc_namespace *ipc_ns;
	struct dentry *control_dentry;
	kuid_t root_uid;
	kgid_t root_gid;
	struct binderfs_mount_opts mount_opts;
	int device_count;
	struct dentry *proc_log_dir;
};

extern const struct file_operations binder_fops;

extern char *binder_devices_param;

#ifdef CONFIG_ANDROID_BINDERFS
extern bool is_binderfs_device(const struct inode *inode);
extern struct dentry *binderfs_create_file(struct dentry *dir, const char *name,
					   const struct file_operations *fops,
					   void *data);
extern void binderfs_remove_file(struct dentry *dentry);
#else
static inline bool is_binderfs_device(const struct inode *inode)
{
	return false;
}
static inline struct dentry *binderfs_create_file(struct dentry *dir,
					   const char *name,
					   const struct file_operations *fops,
					   void *data)
{
	return NULL;
}
static inline void binderfs_remove_file(struct dentry *dentry) {}
#endif

#ifdef CONFIG_ANDROID_BINDERFS
extern int __init init_binderfs(void);
#else
static inline int __init init_binderfs(void)
{
	return 0;
}
#endif

int binder_stats_show(struct seq_file *m, void *unused);
DEFINE_SHOW_ATTRIBUTE(binder_stats);

int binder_state_show(struct seq_file *m, void *unused);
DEFINE_SHOW_ATTRIBUTE(binder_state);

int binder_transactions_show(struct seq_file *m, void *unused);
DEFINE_SHOW_ATTRIBUTE(binder_transactions);

int binder_transaction_log_show(struct seq_file *m, void *unused);
DEFINE_SHOW_ATTRIBUTE(binder_transaction_log);

struct binder_transaction_log_entry {
	int debug_id;
	int debug_id_done;
	int call_type;
	int from_proc;
	int from_thread;
	int target_handle;
	int to_proc;
	int to_thread;
	int to_node;
	int data_size;
	int offsets_size;
	int return_error_line;
	uint32_t return_error;
	uint32_t return_error_param;
	char context_name[BINDERFS_MAX_NAME + 1];
};

struct binder_transaction_log {
	atomic_t cur;
	bool full;
	struct binder_transaction_log_entry entry[32];
};

/**
 * struct binder_proc_ext - binder process bookkeeping
 * @proc:            element for binder_procs list
 * @cred                  struct cred associated with the `struct file`
 *                        in binder_open()
 *                        (invariant after initialized)
 *
 * Extended binder_proc -- needed to add the "cred" field without
 * changing the KMI for binder_proc.
 */
struct binder_proc_ext {
	struct binder_proc proc;
	const struct cred *cred;
};

static inline const struct cred *binder_get_cred(struct binder_proc *proc)
{
	struct binder_proc_ext *eproc;

	eproc = container_of(proc, struct binder_proc_ext, proc);
	return eproc->cred;
}

/**
 * struct binder_txn_fd_fixup - transaction fd fixup list element
 * @fixup_entry:          list entry
 * @file:                 struct file to be associated with new fd
 * @offset:               offset in buffer data to this fixup
 *
 * List element for fd fixups in a transaction. Since file
 * descriptors need to be allocated in the context of the
 * target process, we pass each fd to be processed in this
 * struct.
 */
struct binder_txn_fd_fixup {
	struct list_head fixup_entry;
	struct file *file;
	size_t offset;
};

extern struct binder_transaction_log binder_transaction_log;
extern struct binder_transaction_log binder_transaction_log_failed;
#endif /* _LINUX_BINDER_INTERNAL_H */
