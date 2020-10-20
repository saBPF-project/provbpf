/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <linux/limits.h>

#include "sockaddr.h"
#include "linux/provenance.h"
#include "linux/provenance_types.h"
#include "camflow_bpf_id.h"

#include "kern_bpf_maps.h"
#include "kern_bpf_common.h"
#include "kern_bpf_node.h"
#include "kern_bpf_task.h"
#include "kern_bpf_inode.h"
#include "kern_bpf_cred.h"
#include "kern_bpf_iattr.h"
#include "kern_bpf_relation.h"

char _license[] SEC("license") = "GPL";

/* LSM hooks names can be reference here:
 * https://elixir.bootlin.com/linux/v5.8/source/include/linux/lsm_hook_defs.h
 * Template is: SEC("lsm/HOOK_NAMES")
 */


/*!
 * @brief Record provenance when task_alloc is triggered.
 *
 * Record provenance relation RL_PROC_READ (by calling "uses_two" function)
 * and RL_CLONE (by calling "informs" function).
 * We create a ACT_TASK node for the newly allocated task.
 * Since @cred is shared by all threads, we use @cred to save process's
 * provenance, and @task to save provenance of each thread.
 * @param task Task being allocated.
 * @param clone_flags The flags indicating what should be shared.
 * @return 0 if no error occurred. Other error codes unknown.
 *
 */
SEC("lsm/task_alloc")
int BPF_PROG(task_alloc, struct task_struct *task, unsigned long clone_flags) {
    union prov_elt *ptr_prov, *ptr_prov_current, *ptr_prov_cred;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    struct cred* current_cred;
    bpf_probe_read(&current_cred, sizeof(current_cred), &current_task->real_cred);

    ptr_prov_current = get_or_create_task_prov(current_task);
    if (!ptr_prov_current)
        return 0;

    ptr_prov = get_or_create_task_prov(task);
    if (!ptr_prov)
        return 0;

    ptr_prov_cred = get_or_create_cred_prov(current_cred, current_task);
    if (!ptr_prov_cred)
        return 0;

    uses_two(RL_PROC_READ, ptr_prov_cred, false, ptr_prov_current, false, NULL, clone_flags);
    informs(RL_CLONE, ptr_prov_current, false, ptr_prov, false, NULL, clone_flags);
    return 0;
}

/*!
 * @brief Record provenance when task_free hook is triggered.
 *
 * Record provenance relation RL_TERMINATE_TASK by calling function
 * "record_terminate".
 * @param task The task in question (i.e., to be free).
 *
 */
SEC("lsm/task_free")
int BPF_PROG(task_free, struct task_struct *task) {
    uint64_t key;
    get_key(task);
    union prov_elt *ptr_prov;

    ptr_prov = get_or_create_task_prov(task);
    if(!ptr_prov) // something is wrong
        return 0;

    /* Record task terminate */
    record_terminate(RL_TERMINATE_TASK, ptr_prov, false);

    /* Delete task provenance since the task no longer exists */
    bpf_map_delete_elem(&task_map, &key);

    return 0;
}
//
// /*!
//  * @brief Record provenance when task_fix_setuid hook is triggered.
//  *
//  * This hook is triggered when updating the module's state after setting one or
//  * more of the user identity attributes of the current process.
//  * The @flags parameter indicates which of the set*uid system calls invoked this
//  * hook.
//  * If @new is the set of credentials that will be installed,
//  * modifications should be made to this rather than to @current->cred.
//  * Information flows from @old to current process and then eventually flows to
//  * @new (since modification should be made to @new instead of @current->cred).
//  * Record provenance relation RL_SETUID.
//  * @param new The set of credentials that will be installed
//  * @param old The set of credentials that are being replaced.
//  * @param flags One of the LSM_SETID_* values.
//  * @return 0 if no error occurred. Other error codes unknown.
//  *
//  */
SEC("lsm/task_fix_setuid")
int BPF_PROG(task_fix_setuid, struct cred *new, const struct cred *old, int flags) {
    union prov_elt *ptr_prov_new_cred, *ptr_prov_old_cred, *ptr_prov_task;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();

    ptr_prov_new_cred = get_or_create_cred_prov(new, current_task);
    if (!ptr_prov_new_cred) {
      return 0;
    }
    ptr_prov_old_cred = get_or_create_cred_prov(old, current_task);
    if (!ptr_prov_old_cred) {
      return 0;
    }
    ptr_prov_task = get_or_create_task_prov(current_task);
    if (!ptr_prov_task) {
      return 0;
    }

    generates(RL_SETUID, current_task, ptr_prov_old_cred, false, ptr_prov_task, false, ptr_prov_new_cred, false, NULL, flags);

    return 0;
}

/*!
 * @brief Record provenance when task_setpgid hook is triggered.
 *
 * Update the module's state after setting one or more of the group
 * identity attributes of the current process.  The @flags parameter
 * indicates which of the set*gid system calls invoked this hook.
 * @new is the set of credentials that will be installed.  Modifications
 * should be made to this rather than to @current->cred.
 * @old is the set of credentials that are being replaced
 * @flags contains one of the LSM_SETID_* values.
 * Return 0 on success.
 */
SEC("lsm/task_fix_setgid")
int BPF_PROG(task_fix_setgid, struct cred *new, const struct cred *old, int flags) {
    union prov_elt *ptr_prov_new_cred, *ptr_prov_old_cred, *ptr_prov_task;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();

    ptr_prov_new_cred = get_or_create_cred_prov(new, current_task);
    if (!ptr_prov_new_cred) {
      return 0;
    }
    ptr_prov_old_cred = get_or_create_cred_prov(old, current_task);
    if (!ptr_prov_old_cred) {
      return 0;
    }
    ptr_prov_task = get_or_create_task_prov(current_task);
    if (!ptr_prov_task) {
      return 0;
    }

    generates(RL_SETGID, current_task, ptr_prov_old_cred, false, ptr_prov_task, false, ptr_prov_new_cred, false, NULL, flags);

    return 0;
}

/*!
 * @brief: Record provenance when task_getpgid hook is triggered.
 *
 * Check permission before getting the process group identifier of the
 * process @p.
 * @p contains the task_struct for the process.
 * Return 0 if permission is granted.
 */
SEC("lsm/task_getpgid")
int BPF_PROG(task_getpgid, struct task_struct *p) {
    union prov_elt *ptr_prov, *ptr_prov_current_task, *ptr_prov_current_cred;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    const struct cred *current_task_cred, *p_task_cred;
    bpf_probe_read(&current_task_cred, sizeof(current_task_cred), &current_task->cred);
    bpf_probe_read(&p_task_cred, sizeof(p_task_cred), &p->cred);

    ptr_prov_current_cred = get_or_create_cred_prov(current_task_cred, current_task);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_current_task = get_or_create_task_prov(current_task);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov = get_or_create_cred_prov(p_task_cred, p);
    if (!ptr_prov) {
      return 0;
    }

    uses(RL_GETGID, current_task, ptr_prov, false, ptr_prov_current_task, false, ptr_prov_current_cred, false, NULL, 0);
    return 0;
}

/*!
 * @brief Record provenance when inode_alloc_security hook is triggered.
 *
 * This hook is triggered when allocating and attaching a security structure to
 * @inode->i_security.
 * The i_security field is initialized to NULL when the inode structure is
 * allocated.
 * When i_security field is initialized, we also initialize i_provenance field
 * of the inode.
 * Therefore, we create a new ENT_INODE_UNKNOWN provenance entry.
 * UUID information from @i_sb (superblock) is copied to the new inode's
 * provenance entry.
 * We then call function "refresh_inode_provenance" to obtain more information
 * about the inode.
 * No information flow occurs.
 * @param inode The inode structure.
 * @return 0 if operation was successful; -ENOMEM if no memory can be allocated
 * for the new inode provenance entry. Other error codes unknown.
 *
 */
SEC("lsm/inode_alloc_security")
int BPF_PROG(inode_alloc_security, struct inode *inode) {
    union prov_elt *ptr_prov;

    ptr_prov = get_or_create_inode_prov(inode);
    if(!ptr_prov) // something is wrong
        return 0;

    record_provenance(false, ptr_prov);

    return 0;
}

/*!
 * @brief Record provenance when inode_free_security hook is triggered.
 *
 * This hook is triggered when deallocating the inode security structure and
 * set @inode->i_security to NULL.
 * Record provenance relation RL_FREED by calling "record_terminate" function.
 * Free kernel memory allocated for provenance entry of the inode in question.
 * Set the provenance pointer in @inode to NULL.
 * @param inode The inode structure whose security is to be freed.
 *
 */
SEC("lsm/inode_free_security")
int BPF_PROG(inode_free_security, struct inode *inode) {
    uint64_t key = get_key(inode);
    union prov_elt *ptr_prov;

    ptr_prov = get_or_create_inode_prov(inode);
    if(!ptr_prov) // something is wrong
        return 0;

    /* Record inode freed */
    record_terminate(RL_FREED, ptr_prov, false);

    bpf_map_delete_elem(&inode_map, &key);
    return 0;
}

/*!
 * @brief Record provenance when inode_create hook is triggered.
 *
 * This hook is trigger when checking permission to create a regular file.
 * Record provenance relation RL_INODE_CREATE.
 * Information flows from current process's cred's to the process, and
 * eventually to the parent's inode.
 * @param dir Inode structure of the parent of the new file.
 * @param dentry The dentry structure for the file to be created.
 * @param mode The file mode of the file to be created.
 * @return 0 if permission is granted; -ENOMEM if parent's inode's provenance
 * entry is NULL. Other error codes unknown.
 *
 */
SEC("lsm/inode_create")
int BPF_PROG(inode_create, struct inode *dir, struct dentry *dentry, umode_t mode) {
    union prov_elt *ptr_prov_current_cred, *ptr_prov_current_task, *ptr_prov_inode;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    const struct cred *current_task_cred;
    bpf_probe_read(&current_task_cred, sizeof(current_task_cred), &current_task->cred);

    ptr_prov_current_cred = get_or_create_cred_prov(current_task_cred, current_task);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_current_task = get_or_create_task_prov(current_task);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov_inode = get_or_create_inode_prov(dir);
    if (!ptr_prov_inode) {
      return 0;
    }

    generates(RL_INODE_CREATE, current_task, ptr_prov_current_cred, false, ptr_prov_current_task, false, ptr_prov_inode, false, NULL, mode);

    return 0;
}

/*!
 * @brief Record provenance when inode_permission hook is triggered.
 *
 * This hook is triggered when checking permission before accessing an inode.
 * This hook is called by the existing Linux permission function,
 * so a security module can use it to provide additional checking for existing
 * Linux permission checks.
 * Notice that this hook is called when a file is opened (as well as many other
 * operations),
 * whereas the file_security_ops permission hook is called when the actual
 * read/write operations are performed.
 * Depending on the permission specified in @mask,
 * Zero or more relation may be recorded during this permission check.
 * If permission is:
 * 1. MAY_EXEC: record provenance relation RL_PERM_EXEC, and
 * 2. MAY_READ: record provenance relation MAY_READ, and
 * 3. MAY_APPEND: record provenance relation RL_PERM_APPEND, and
 * 4. MAY_WRITE: record provenance relation RL_PERM_WRITE.
 * Information flows from @inode's provenance to the current process that
 * attempts to access the inode, and eventually to the cred of the task.
 * Provenance relation is not recorded if the inode to be access is private
 * or if the inode's provenance entry does not exist.
 * @param inode The inode structure to check.
 * @param mask The permission mask.
 * @return 0 if permission is granted; -ENOMEM if @inode's provenance does not
 * exist. Other error codes unknown.
 */
SEC("lsm/inode_permission")
int BPF_PROG(inode_permission, struct inode *inode, int mask) {
    union prov_elt *ptr_prov_current_cred, *ptr_prov_current_task, *ptr_prov_inode;
    ptr_prov_current_cred = NULL;
    ptr_prov_current_task = NULL;
    ptr_prov_inode = NULL;

    if (!mask) {
      return 0;
    }
    // if inode IS_PRIVATE is unlikely
    if (__builtin_expect(IS_PRIVATE(inode), 0)) {
      return 0;
    }

    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    const struct cred *current_task_cred;
    bpf_probe_read(&current_task_cred, sizeof(current_task_cred), &current_task->cred);

    ptr_prov_current_cred = get_or_create_cred_prov(current_task_cred, current_task);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_current_task = get_or_create_task_prov(current_task);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov_inode = get_or_create_inode_prov(inode);
    if (!ptr_prov_inode) {
      return 0;
    }

    // Left commented due to producing significant amount of output.
    // if (mask & MAY_EXEC) {
    //   uses(RL_PERM_EXEC, current_task, ptr_prov_inode, false, ptr_prov_current_task, false, ptr_prov_current_cred, false, NULL, mask);
    // } else if (mask & MAY_READ) {
    //   uses(RL_PERM_READ, current_task, ptr_prov_inode, false, ptr_prov_current_task, false, ptr_prov_current_cred, false, NULL, mask);
    // } else if (mask & MAY_APPEND) {
    //   uses(RL_PERM_APPEND, current_task, ptr_prov_inode, false, ptr_prov_current_task, false, ptr_prov_current_cred, false, NULL, mask);
    // } else if (mask & MAY_WRITE) {
    //   uses(RL_PERM_WRITE, current_task, ptr_prov_inode, false, ptr_prov_current_task, false, ptr_prov_current_cred, false, NULL, mask);
    // }

    return 0;
}

/*!
 * @brief Record provenance when inode_link hook is triggered.
 *
 * This hook is triggered when checking permission before creating a new hard
 * link to a file.
 * We obtain the provenance of current process and its cred, as well as
 * provenance of inode or parent directory of new link.
 * We also get the provenance of existing link to the file.
 * Record two provenance relations RL_LINK.
 * Information flows:
 * 1. From cred of the current process to the process, and eventually to the
 * inode of parent directory of new link, and,
 * 2. From cred of the current process to the process, and eventually to the
 * dentry of the existing link to the file, and
 * 3. From the inode of parent directory of new link to the dentry of the
 * existing link to the file.
 * @param old_dentry The dentry structure for an existing link to the file.
 * @parm dir The inode structure of the parent directory of the new link.
 * @param new_dentry The dentry structure for the new link.
 * @return 0 if permission is granted; -ENOMEM if either the dentry provenance
 * of the existing link to the file or the inode provenance of the new parent
 * directory of new link does not exist.
 */
SEC("lsm/inode_link")
int BPF_PROG(inode_link, struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry) {
    union prov_elt *ptr_prov_current_cred, *ptr_prov_current_task, *ptr_prov;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    const struct cred *current_task_cred;
    bpf_probe_read(&current_task_cred, sizeof(current_task_cred), &current_task->cred);

    ptr_prov_current_cred = get_or_create_cred_prov(current_task_cred, current_task);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_current_task = get_or_create_task_prov(current_task);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov = get_or_create_inode_prov(old_dentry->d_inode);
    if (!ptr_prov) {
      return 0;
    }

    generates(RL_LINK, current_task, ptr_prov_current_cred, false, ptr_prov_current_task, false, ptr_prov, false, NULL, 0);

    return 0;
}

/*!
 * @brief Record provenance when inode_unlink hook is triggered.
 *
 * Check the permission to remove a hard link to a file.
 * @dir contains the inode structure of parent directory of the file.
 * @dentry contains the dentry structure for file to be unlinked.
 * Return 0 if permission is granted.
 */
SEC("lsm/inode_unlink")
int BPF_PROG(inode_unlink, struct inode *dir, struct dentry *dentry) {
    union prov_elt *ptr_prov_current_cred, *ptr_prov_current_task, *ptr_prov;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    const struct cred *current_task_cred;
    bpf_probe_read(&current_task_cred, sizeof(current_task_cred), &current_task->cred);

    ptr_prov_current_cred = get_or_create_cred_prov(current_task_cred, current_task);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_current_task = get_or_create_task_prov(current_task);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov = get_or_create_inode_prov(dentry->d_inode);
    if (!ptr_prov) {
      return 0;
    }

    generates(RL_UNLINK, current_task, ptr_prov_current_cred, false, ptr_prov_current_task, false, ptr_prov, false, NULL, 0);

    return 0;
}

/*!
 * @brief Record provenance when inode_symlink hook is triggered.
 *
 * Check the permission to create a symbolic link to a file.
 * @dir contains the inode structure of parent directory of the symbolic link.
 * @dentry contains the dentry structure of the symbolic link.
 * @old_name contains the pathname of file.
 * Return 0 if permission is granted.
 */
SEC("lsm/inode_symlink")
int BPF_PROG(inode_symlink, struct inode *dir, struct dentry *dentry, const char *old_name) {
    union prov_elt *ptr_prov_current_cred, *ptr_prov_current_task, *ptr_prov;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    const struct cred *current_task_cred;
    bpf_probe_read(&current_task_cred, sizeof(current_task_cred), &current_task->cred);

    ptr_prov_current_cred = get_or_create_cred_prov(current_task_cred, current_task);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_current_task = get_or_create_task_prov(current_task);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov = get_or_create_inode_prov(dentry->d_inode);
    if (!ptr_prov) {
      return 0;
    }

    generates(RL_SYMLINK, current_task, ptr_prov_current_cred, false, ptr_prov_current_task, false, ptr_prov, false, NULL, 0);

    return 0;
}

/*!
 * @brief Record provenance when inode_rename hook is triggered.
 *
 * This hook is triggered when checking for permission to rename a file or
 * directory.
 * @param old_dir The inode structure for parent of the old link.
 * @param old_dentry The dentry structure of the old link.
 * @param new_dir The inode structure for parent of the new link.
 * @param new_dentry The dentry structure of the new link.
 * @return Error code is the same as in "provenance_inode_link" function.
 *
 */
SEC("lsm/inode_rename")
int BPF_PROG(inode_rename, struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry) {
    union prov_elt *ptr_prov_current_cred, *ptr_prov_current_task, *ptr_prov;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    const struct cred *current_task_cred;
    bpf_probe_read(&current_task_cred, sizeof(current_task_cred), &current_task->cred);

    ptr_prov_current_cred = get_or_create_cred_prov(current_task_cred, current_task);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_current_task = get_or_create_task_prov(current_task);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov = get_or_create_inode_prov(old_dentry->d_inode);
    if (!ptr_prov) {
      return 0;
    }

    generates(RL_RENAME, current_task, ptr_prov_current_cred, false, ptr_prov_current_task, false, ptr_prov, false, NULL, 0);

    return 0;
}

/*!
 * @brief Record provenance when inode_setattr hook is triggered.
 *
 * This hook is triggered when checking permission before setting file
 * attributes.
 * Note that the kernel call to notify_change is performed from several
 * locations, whenever file attributes change (such as when a file is truncated,
 * chown/chmod operations transferring disk quotas, etc).
 * We create a new provenance node ENT_IATTR, and update its information based
 * on @attr.
 * Record provenance relation RL_SETATTR.
 * Record provenance relation RL_SETATTR_INODE.
 * Information flows from cred of the current process to the process, and
 * eventually to the inode attribute to set the attributes.
 * Information also flows from inode attribute to the inode whose attributes
 * are to be set.
 * We also persistant the inode's provenance.
 * @param dentry The dentry structure for the file.
 * @param attr The iattr structure containing the new file attributes.
 * @return 0 if permission is granted; -ENOMEM if inode provenance of the file
 * is NULL; -ENOMEM if no memory can be allocated for a new ENT_IATTR provenance
 * entry. Other error codes unknown.
 *
 */
SEC("lsm/inode_setattr")
int BPF_PROG(inode_setattr, struct dentry *dentry, struct iattr *attr) {
    union prov_elt *ptr_prov_current_cred, *ptr_prov_current_task, *ptr_prov_inode, *ptr_prov_iattr;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    const struct cred *current_task_cred;
    bpf_probe_read(&current_task_cred, sizeof(current_task_cred), &current_task->cred);

    ptr_prov_current_cred = get_or_create_cred_prov(current_task_cred, current_task);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_current_task = get_or_create_task_prov(current_task);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov_inode = get_or_create_inode_prov(dentry->d_inode);
    if (!ptr_prov_inode) {
      return 0;
    }
    ptr_prov_iattr = get_or_create_iattr_prov(attr);
    if (!ptr_prov_iattr) {
      return 0;
    }

    generates(RL_SETATTR, current_task, ptr_prov_current_cred, false, ptr_prov_current_task, false, ptr_prov_iattr, false, NULL, 0);
    derives(RL_SETATTR_INODE, ptr_prov_iattr, false, ptr_prov_inode, false, NULL, 0);

    return 0;
}


/*!
 * @brief Record provenance when inode_getattr hook is triggered.
 *
 * This hook is triggered when checking permission before obtaining file
 * attributes.
 * Record provenance relation RL_GETATTR.
 * Information flows from the inode of the file to the calling process, and
 * eventually to the process's cred.
 * @param path The path structure for the file.
 * @return 0 if permission is granted; -ENOMEM if the provenance entry of the
 * file is NULL. Other error codes unknown.
 *
 */
SEC("lsm/inode_getattr")
int BPF_PROG(inode_getattr, const struct path *path) {
    union prov_elt *ptr_prov_current_cred, *ptr_prov_current_task, *ptr_prov_inode;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    const struct cred *current_task_cred;
    bpf_probe_read(&current_task_cred, sizeof(current_task_cred), &current_task->cred);

    ptr_prov_current_cred = get_or_create_cred_prov(current_task_cred, current_task);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_current_task = get_or_create_task_prov(current_task);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov_inode = get_or_create_inode_prov(path->dentry->d_inode);
    if (!ptr_prov_inode) {
      return 0;
    }

    uses(RL_GETATTR, current_task, ptr_prov_inode, false, ptr_prov_current_task, false, ptr_prov_current_cred, false, NULL, 0);

    return 0;
}

/*!
 * @brief Record provenance when inode_readlink hook is triggered.
 *
 * This hook is triggered when checking the permission to read the symbolic
 * link.
 * Record provenance relation RL_READ_LINK.
 * Information flows from the link file to the calling process, and eventually
 * to its cred.
 * @param dentry The dentry structure for the file link.
 * @return 0 if permission is granted; -ENOMEM if the link file's provenance
 * entry is NULL. Other error codes unknown.
 *
 */
SEC("lsm/inode_readlink")
int BPF_PROG(inode_readlink, struct dentry *dentry) {
    union prov_elt *ptr_prov_current_cred, *ptr_prov_current_task, *ptr_prov_inode;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    const struct cred *current_task_cred;
    bpf_probe_read(&current_task_cred, sizeof(current_task_cred), &current_task->cred);

    ptr_prov_current_cred = get_or_create_cred_prov(current_task_cred, current_task);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_current_task = get_or_create_task_prov(current_task);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov_inode = get_or_create_inode_prov(dentry->d_inode);
    if (!ptr_prov_inode) {
      return 0;
    }

    uses(RL_READ_LINK, current_task, ptr_prov_inode, false, ptr_prov_current_task, false, ptr_prov_current_cred, false, NULL, 0);

    return 0;
}

/*!
 * @brief Record provenance when inode_post_setxattr hook is triggered.
 *
 * This hook is triggered when updating inode security field after successful
 * setxattr operation.
 * The relations are recorded through "record_write_xattr" function.
 * RL_SETXATTR is one of the relations to be recorded.
 * The relations may not be recorded for the following reasons:
 * 1. The name of the extended attribute is provenance (do not capture
 * provenance of CamFlow provenance ops), or
 * 2. inode provenance entry is NULL.
 * @param dentry The dentry structure for the file.
 * @param name The name of the extended attribute.
 * @param value The value of that attribute.
 * @param size The size of the value.
 * @param flags The operational flags.
 *
 */
SEC("lsm/inode_post_setxattr")
int BPF_PROG(inode_post_setxattr, struct dentry *dentry, const char *name,const void *value, size_t size, int flags) {
    union prov_elt *ptr_prov_current_cred, *ptr_prov_current_task, *ptr_prov_inode;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    const struct cred *current_task_cred;
    bpf_probe_read(&current_task_cred, sizeof(current_task_cred), &current_task->cred);

    ptr_prov_current_cred = get_or_create_cred_prov(current_task_cred, current_task);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_current_task = get_or_create_task_prov(current_task);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov_inode = get_or_create_inode_prov(dentry->d_inode);
    if (!ptr_prov_inode) {
      return 0;
    }

    record_write_xattr(RL_SETXATTR, ptr_prov_inode, ptr_prov_current_task, ptr_prov_current_cred, name, value, size, flags);

    return 0;
}

/*!
 * @brief Record provenance when inode_getxattr hook is triggered.
 *
 * This hook is triggered when checking permission before obtaining the extended
 * attributes.
 * The relations are recorded through "record_read_xattr" function.
 * The relations may not be recorded for the following reasons:
 * 1. The name of the extended attribute is provenance (do not capture
 * provenance of CamFlow provenance ops), or
 * 2. inode provenance entry is NULL.
 * @param dentry The dentry structure for the file.
 * @param name The name of the extended attribute.
 * @return 0 if no error occurred; -ENOMEM if inode provenance is NULL; other
 * error codes inherited from "record_read_xattr" function.
 *
 */
SEC("lsm/inode_getxattr")
int BPF_PROG(inode_getxattr, struct dentry *dentry, const char *name) {
    union prov_elt *ptr_prov_current_cred, *ptr_prov_current_task, *ptr_prov_inode;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    const struct cred *current_task_cred;
    bpf_probe_read(&current_task_cred, sizeof(current_task_cred), &current_task->cred);

    ptr_prov_current_cred = get_or_create_cred_prov(current_task_cred, current_task);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_current_task = get_or_create_task_prov(current_task);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov_inode = get_or_create_inode_prov(dentry->d_inode);
    if (!ptr_prov_inode) {
      return 0;
    }

    record_read_xattr(ptr_prov_current_cred, ptr_prov_current_task, ptr_prov_inode, name);

    return 0;
}

/*!
 * @brief Record provenance when inode_listxattr hook is triggered.
 *
 * This hook is triggered when checking permission before obtaining the list of
 * extended attribute names for @dentry.
 * Record provenance relation RL_LSTXATTR.
 * Information flows from inode (whose xattrs are of interests) to calling task
 * process, and eventually to its cred.
 * The relation may not be recorded if inode provenance entry is NULL.
 * @param dentry The dentry structure for the file.
 * @return 0 if no error occurred; -ENOMEM if inode provenance is NULL.
 */
SEC("lsm/inode_listxattr")
int BPF_PROG(inode_listxattr, struct dentry *dentry) {
    union prov_elt *ptr_prov_current_cred, *ptr_prov_current_task, *ptr_prov_inode;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    const struct cred *current_task_cred;
    bpf_probe_read(&current_task_cred, sizeof(current_task_cred), &current_task->cred);

    ptr_prov_current_cred = get_or_create_cred_prov(current_task_cred, current_task);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_current_task = get_or_create_task_prov(current_task);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov_inode = get_or_create_inode_prov(dentry->d_inode);
    if (!ptr_prov_inode) {
      return 0;
    }

    uses(RL_LSTXATTR, current_task, ptr_prov_inode, false, ptr_prov_current_task, false, ptr_prov_current_cred, false, NULL, 0);

    return 0;
}

/*!
 * @brief Record provenance when inode_removexattr hook is triggered.
 *
 * This hook is triggered when checking permission before removing the extended
 * attribute identified by @name for @dentry.
 * The relations are recorded through "record_write_xattr".
 * RL_RMVXATTR is one of the relations to be recorded.
 * The relations may not be recorded for the following reasons:
 * 1. The name of the extended attribute is provenance (do not capture
 * provenance of CamFlow provenance ops), or
 * 2. inode provenance entry is NULL.
 * @param dentry The dentry structure for the file.
 * @param name The name of the extended attribute.
 *
 */
SEC("lsm/inode_removexattr")
int BPF_PROG(inode_removexattr, struct dentry *dentry, const char *name) {
    union prov_elt *ptr_prov_current_cred, *ptr_prov_current_task, *ptr_prov_inode;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    const struct cred *current_task_cred;
    bpf_probe_read(&current_task_cred, sizeof(current_task_cred), &current_task->cred);

    ptr_prov_current_cred = get_or_create_cred_prov(current_task_cred, current_task);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_current_task = get_or_create_task_prov(current_task);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov_inode = get_or_create_inode_prov(dentry->d_inode);
    if (!ptr_prov_inode) {
      return 0;
    }

    record_write_xattr(RL_RMVXATTR, ptr_prov_inode, ptr_prov_current_task, ptr_prov_current_cred, name, NULL, 0, 0);

    return 0;
}

/*!
 * @brief Record provenance when cred_alloc_blank hook is triggered.
 *
 * This hook is triggered when allocating sufficient memory and attaching to
 * @cred such that cred_transfer() will not get ENOMEM.
 * Therefore, no information flow occurred.
 * We simply create a ENT_PROC provenance node and associate the provenance
 * entry to the newly allocated @cred.
 * @param cred Points to the new credentials.
 * @param gfp Indicates the atomicity of any memory allocations.
 * @return 0 if no error occurred; -ENOMEM if no memory can be allocated for
 * the new provenance entry. Other error codes unknown.
 *
 */
SEC("lsm/cred_alloc_blank")
int BPF_PROG(cred_alloc_blank, struct cred *cred, gfp_t gfp) {
    union prov_elt *ptr_prov;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    struct cred *current_cred;
    bpf_probe_read(&current_cred, sizeof(current_cred), &current_task->real_cred);
    kuid_t current_cred_uid;
    kgid_t current_cred_gid;
    bpf_probe_read(&current_cred_uid, sizeof(current_cred_uid), &current_cred->uid);
    bpf_probe_read(&current_cred_gid, sizeof(current_cred_uid), &current_cred->gid);

    ptr_prov = (current_cred_uid.val == cred->uid.val && current_cred_gid.val == cred->gid.val) ? get_or_create_cred_prov(cred, current_task) : get_or_create_cred_prov(NULL, current_task);
    if (!ptr_prov) {
      return 0;
    }

    record_provenance(false, ptr_prov);

    return 0;
}

/*!
 * @brief Record provenance when cred_free hook is triggered.
 *
 * This hook is triggered when deallocating and clearing the cred->security
 * field in a set of credentials. Record provenance relation RL_TERMINATE_PROC
 * by calling "record_terminate" function.
 * @param cred Points to the credentials to be freed.
 *
 */
SEC("lsm/cred_free")
int BPF_PROG(cred_free, struct cred *cred) {
    uint64_t key = get_key(cred);
    union prov_elt *ptr_prov;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    struct cred *current_cred;
    bpf_probe_read(&current_cred, sizeof(current_cred), &current_task->real_cred);
    kuid_t current_cred_uid;
    kgid_t current_cred_gid;
    bpf_probe_read(&current_cred_uid, sizeof(current_cred_uid), &current_cred->uid);
    bpf_probe_read(&current_cred_gid, sizeof(current_cred_uid), &current_cred->gid);

    ptr_prov = (current_cred_uid.val == cred->uid.val && current_cred_gid.val == cred->gid.val) ? get_or_create_cred_prov(cred, current_task) : get_or_create_cred_prov(NULL, current_task);
    if (!ptr_prov) {
      return 0;
    }

    // Record cred freed
    record_terminate(RL_TERMINATE_PROC, ptr_prov, false);

    bpf_map_delete_elem(&cred_map, &key);
    return 0;
}

/*!
 * @brief Record provenance when cred_prepare hook is triggered.
 *
 * This hook is triggered when preparing a new set of credentials by copying
 * the data from the old set.
 * Record provenance relation RL_CLONE_MEM.
 * We create a new ENT_PROC provenance entry for the new cred.
 * Information flows from old cred to the process that is preparing the new
 * cred.
 * @param new Points to the new credentials.
 * @param old Points to the original credentials.
 * @param gfp Indicates the atomicity of any memory allocations.
 * @return 0 if no error occured. Other error codes unknown.
 *
 */
SEC("lsm/cred_prepare")
int BPF_PROG(cred_prepare, struct cred *new, const struct cred *old, gfp_t gfp) {
    union prov_elt *ptr_prov_new, *ptr_prov_old, *ptr_prov_task;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    struct cred *current_cred;
    bpf_probe_read(&current_cred, sizeof(current_cred), &current_task->real_cred);
    kuid_t current_cred_uid;
    kgid_t current_cred_gid;
    bpf_probe_read(&current_cred_uid, sizeof(current_cred_uid), &current_cred->uid);
    bpf_probe_read(&current_cred_gid, sizeof(current_cred_uid), &current_cred->gid);

    ptr_prov_new = (current_cred_uid.val == new->uid.val && current_cred_gid.val == new->gid.val) ? get_or_create_cred_prov(new, current_task) : get_or_create_cred_prov(NULL, current_task);
    if (!ptr_prov_new) {
      return 0;
    }
    ptr_prov_old = (current_cred_uid.val == old->uid.val && current_cred_gid.val == old->gid.val) ? get_or_create_cred_prov(old, current_task) : get_or_create_cred_prov(NULL, current_task);
    if (!ptr_prov_old) {
      return 0;
    }
    ptr_prov_task = get_or_create_task_prov(current_task);
    if (!ptr_prov_task) {
      return 0;
    }

    generates(RL_CLONE_MEM, current_task, ptr_prov_old, false, ptr_prov_task, false, ptr_prov_new, false, NULL, 0);

    return 0;
}
