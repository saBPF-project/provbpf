/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020-2021 Harvard University
 * Copyright (C) 2020-2021 University of Bristol
 *
 * Author: Thomas Pasquier <thomas.pasquier@bristol.ac.uk>
 * Author: Bogdan Stelea <bs17580@bristol.ac.uk>
 * Author: Soo Yee Lim <sooyee.lim@bristol.ac.uk>
 * Author: Xueyuan "Michael" Han <hanx@g.harvard.edu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 */
#include "kern/vmlinux.h"

#include <linux/libc-compat.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <linux/limits.h>

#include "kern/sockaddr.h"

#include "shared/prov_struct.h"
#include "shared/prov_types.h"
#include "shared/id.h"
#include "shared/policy.h"

#include "kern/maps.h"
#include "kern/common.h"
#include "kern/node.h"
#include "kern/task.h"
#include "kern/inode.h"
#include "kern/cred.h"
#include "kern/msg_msg.h"
#include "kern/ipc_perm.h"
#include "kern/iattr.h"
#include "kern/relation.h"
#include "kern/net.h"

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
#ifndef PROV_FILTER_TASK_ALLOC_OFF
SEC("lsm/task_alloc")
int BPF_PROG(task_alloc, struct task_struct *task, unsigned long clone_flags) {
    union prov_elt *ptr_prov, *ptr_prov_current;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();

    ptr_prov_current = get_or_create_task_prov(current_task);
    if (!ptr_prov_current)
        return 0;

    ptr_prov = get_or_create_task_prov(task);
    if (!ptr_prov)
        return 0;

    //uses_two(RL_PROC_READ, ptr_prov_cred, false, ptr_prov_current, false, NULL, clone_flags);
    informs(RL_CLONE, ptr_prov_current, ptr_prov, NULL, clone_flags);
    return 0;
}
#endif

/*!
 * @brief Record provenance when task_free hook is triggered.
 *
 * Record provenance relation RL_TERMINATE_TASK by calling function
 * "record_terminate".
 * @param task The task in question (i.e., to be free).
 *
 */
#ifndef PROV_FILTER_TASK_FREE_OFF
SEC("lsm/task_free")
int BPF_PROG(task_free, struct task_struct *task) {
    union prov_elt *ptr_prov;

    ptr_prov = get_or_create_task_prov(task);
    if(!ptr_prov) // something is wrong
        return 0;

    /* Record task terminate */
    record_terminate(RL_TERMINATE_TASK, ptr_prov);

    /* Delete task provenance since the task no longer exists */
    bpf_task_storage_delete(&task_storage_map, task);

    return 0;
}
#endif

/*!
 * @brief Record provenance when task_fix_setuid hook is triggered.
 *
 * This hook is triggered when updating the module's state after setting one or
 * more of the user identity attributes of the current process.
 * The @flags parameter indicates which of the set*uid system calls invoked this
 * hook.
 * If @new is the set of credentials that will be installed,
 * modifications should be made to this rather than to @current->cred.
 * Information flows from @old to current process and then eventually flows to
 * @new (since modification should be made to @new instead of @current->cred).
 * Record provenance relation RL_SETUID.
 * @param new The set of credentials that will be installed
 * @param old The set of credentials that are being replaced.
 * @param flags One of the LSM_SETID_* values.
 * @return 0 if no error occurred. Other error codes unknown.
 *
 */
#ifndef PROV_FILTER_TASK_FIX_SETUID_OFF
SEC("lsm/task_fix_setuid")
int BPF_PROG(task_fix_setuid, struct cred *new, const struct cred *old, int flags) {
    union prov_elt *ptr_prov_new_cred, *ptr_prov_old_cred, *ptr_prov_task;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();

    ptr_prov_new_cred = get_or_create_cred_prov(new);
    if (!ptr_prov_new_cred) {
      return 0;
    }
    ptr_prov_old_cred = get_or_create_cred_prov(old);
    if (!ptr_prov_old_cred) {
      return 0;
    }
    ptr_prov_task = get_or_create_task_prov(current_task);
    if (!ptr_prov_task) {
      return 0;
    }

    generates(RL_SETUID, current_task, ptr_prov_old_cred, ptr_prov_task, ptr_prov_new_cred, NULL, flags);

    return 0;
}
#endif

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
#ifndef PROV_FILTER_TASK_FIX_SETGID_OFF
SEC("lsm/task_fix_setgid")
int BPF_PROG(task_fix_setgid, struct cred *new, const struct cred *old, int flags) {
    union prov_elt *ptr_prov_new_cred, *ptr_prov_old_cred, *ptr_prov_task;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();

    ptr_prov_new_cred = get_or_create_cred_prov(new);
    if (!ptr_prov_new_cred) {
      return 0;
    }
    ptr_prov_old_cred = get_or_create_cred_prov(old);
    if (!ptr_prov_old_cred) {
      return 0;
    }
    ptr_prov_task = get_task_provenance(current_task, true);
    if (!ptr_prov_task) {
      return 0;
    }

    generates(RL_SETGID, current_task, ptr_prov_old_cred, ptr_prov_task, ptr_prov_new_cred, NULL, flags);

    return 0;
}
#endif

/*!
 * @brief: Record provenance when task_getpgid hook is triggered.
 *
 * Check permission before getting the process group identifier of the
 * process @p.
 * @p contains the task_struct for the process.
 * Return 0 if permission is granted.
 */
#ifndef PROV_FILTER_TASK_GETPGID_OFF
SEC("lsm/task_getpgid")
int BPF_PROG(task_getpgid, struct task_struct *p) {
    union prov_elt *ptr_prov, *ptr_prov_current_task, *ptr_prov_current_cred;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    struct cred *current_cred, *p_task_cred;
    current_cred = get_task_cred(current_task);
    p_task_cred = get_task_cred(p);

    ptr_prov_current_cred = get_or_create_cred_prov(current_cred);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_current_task = get_task_provenance(current_task, true);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov = get_or_create_cred_prov(p_task_cred);
    if (!ptr_prov) {
      return 0;
    }

    uses(RL_GETGID, current_task, ptr_prov, ptr_prov_current_task, ptr_prov_current_cred, NULL, 0);
    return 0;
}
#endif

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
#ifndef PROV_FILTER_INODE_ALLOC_SECURITY_OFF
SEC("lsm/inode_alloc_security")
int BPF_PROG(inode_alloc_security, struct inode *inode) {
    union prov_elt *ptr_prov;

    if (is_inode_dir(inode))
        return 0;

    ptr_prov = get_or_create_inode_prov(inode);
    if(!ptr_prov) // something is wrong
        return 0;

    record_provenance(false, ptr_prov);

    return 0;
}
#endif

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
#ifndef PROV_FILTER_INODE_FREE_SECURITY_OFF
SEC("lsm/inode_free_security")
int BPF_PROG(inode_free_security, struct inode *inode) {
    union prov_elt *ptr_prov;

    if (is_inode_dir(inode))
        return 0;

    uint64_t key = get_key(inode);
    ptr_prov = get_or_create_inode_prov(inode);
    if(!ptr_prov) // something is wrong
        return 0;

    /* Record inode freed */
    record_terminate(RL_FREED, ptr_prov);

    bpf_map_delete_elem(&inode_map, &key);
    return 0;
}
#endif

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
 /***********************************************************
 * this one is commented out as we do not track directories *
 ************************************************************/
/*#ifndef PROV_FILTER_INODE_CREATE_OFF
SEC("lsm/inode_create")
int BPF_PROG(inode_create, struct inode *dir, struct dentry *dentry, umode_t mode) {
    union prov_elt *ptr_prov_current_cred, *ptr_prov_current_task, *ptr_prov_inode;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    struct cred *current_cred;
    current_cred = get_task_cred(current_task);

    ptr_prov_current_cred = get_or_create_cred_prov(current_cred);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_current_task = get_task_provenance(current_task, true);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov_inode = get_or_create_inode_prov(dir);
    if (!ptr_prov_inode) {
      return 0;
    }

    generates(RL_INODE_CREATE, current_task, ptr_prov_current_cred, ptr_prov_current_task, ptr_prov_inode, NULL, mode);

    return 0;
}
#endif*/

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
#ifndef PROV_FILTER_INODE_PERMISSION_OFF
SEC("lsm/inode_permission")
int BPF_PROG(inode_permission, struct inode *inode, int mask) {
    union prov_elt *ptr_prov_current_cred, *ptr_prov_current_task, *ptr_prov_inode;
    ptr_prov_current_cred = NULL;
    ptr_prov_current_task = NULL;
    ptr_prov_inode = NULL;

    if (is_inode_dir(inode))
        return 0;

    if (!mask)
      return 0;
    // if inode IS_PRIVATE is unlikely
    if (__builtin_expect(IS_PRIVATE(inode), 0)) {
      return 0;
    }

    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    struct cred *current_cred;
    current_cred = get_task_cred(current_task);

    ptr_prov_current_cred = get_or_create_cred_prov(current_cred);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_current_task = get_task_provenance(current_task, true);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov_inode = get_or_create_inode_prov(inode);
    if (!ptr_prov_inode) {
      return 0;
    }

    uint64_t relation_type = 0;

    if (mask & MAY_EXEC) {
      relation_type = RL_PERM_EXEC;
    } else if (mask & MAY_READ) {
      relation_type = RL_PERM_READ;
    } else if (mask & MAY_APPEND) {
      relation_type = RL_PERM_APPEND;
    } else if (mask & MAY_WRITE) {
      relation_type = RL_PERM_WRITE;
    }

    if (relation_type != 0) {
      uses(relation_type, current_task, ptr_prov_inode, ptr_prov_current_task, ptr_prov_current_cred, NULL, mask);
    }

    return 0;
}
#endif

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
#ifndef PROV_FILTER_INODE_LINK_OFF
SEC("lsm/inode_link")
int BPF_PROG(inode_link, struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry) {
    union prov_elt *ptr_prov_current_cred, *ptr_prov_current_task, *ptr_prov;
    struct task_struct *current_task;
    struct cred *current_cred;

    if (is_inode_dir(old_dentry->d_inode))
        return 0;

    current_task = (struct task_struct *)bpf_get_current_task();

    current_cred = get_task_cred(current_task);

    ptr_prov_current_cred = get_or_create_cred_prov(current_cred);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_current_task = get_task_provenance(current_task, true);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov = get_or_create_inode_prov(old_dentry->d_inode);
    if (!ptr_prov) {
      return 0;
    }

    generates(RL_LINK, current_task, ptr_prov_current_cred, ptr_prov_current_task, ptr_prov, NULL, 0);

    return 0;
}
#endif

/*!
 * @brief Record provenance when inode_unlink hook is triggered.
 *
 * Check the permission to remove a hard link to a file.
 * @dir contains the inode structure of parent directory of the file.
 * @dentry contains the dentry structure for file to be unlinked.
 * Return 0 if permission is granted.
 */
#ifndef PROV_FILTER_INODE_UNLINK_OFF
SEC("lsm/inode_unlink")
int BPF_PROG(inode_unlink, struct inode *dir, struct dentry *dentry) {
    union prov_elt *ptr_prov_current_cred, *ptr_prov_current_task, *ptr_prov;
    struct task_struct *current_task;
    struct cred *current_cred;

    if (is_inode_dir(dentry->d_inode))
        return 0;

    current_task = (struct task_struct *)bpf_get_current_task();
    current_cred = get_task_cred(current_task);

    ptr_prov_current_cred = get_or_create_cred_prov(current_cred);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_current_task = get_task_provenance(current_task, true);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov = get_or_create_inode_prov(dentry->d_inode);
    if (!ptr_prov) {
      return 0;
    }

    generates(RL_UNLINK, current_task, ptr_prov_current_cred, ptr_prov_current_task, ptr_prov, NULL, 0);

    return 0;
}
#endif

/*!
 * @brief Record provenance when inode_symlink hook is triggered.
 *
 * Check the permission to create a symbolic link to a file.
 * @dir contains the inode structure of parent directory of the symbolic link.
 * @dentry contains the dentry structure of the symbolic link.
 * @old_name contains the pathname of file.
 * Return 0 if permission is granted.
 */
#ifndef PROV_FILTER_INODE_SYMLINK_OFF
SEC("lsm/inode_symlink")
int BPF_PROG(inode_symlink, struct inode *dir, struct dentry *dentry, const char *old_name) {
    union prov_elt *ptr_prov_current_cred, *ptr_prov_current_task, *ptr_prov;
    struct task_struct *current_task;
    struct cred *current_cred;

    if (is_inode_dir(dentry->d_inode))
        return 0;

    current_task = (struct task_struct *)bpf_get_current_task();
    current_cred = get_task_cred(current_task);

    ptr_prov_current_cred = get_or_create_cred_prov(current_cred);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_current_task = get_task_provenance(current_task, true);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov = get_or_create_inode_prov(dentry->d_inode);
    if (!ptr_prov) {
      return 0;
    }

    generates(RL_SYMLINK, current_task, ptr_prov_current_cred, ptr_prov_current_task, ptr_prov, NULL, 0);

    return 0;
}
#endif

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
#ifndef PROV_FILTER_INODE_RENAME_OFF
SEC("lsm/inode_rename")
int BPF_PROG(inode_rename, struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry) {
    union prov_elt *ptr_prov_current_cred, *ptr_prov_current_task, *ptr_prov;
    struct task_struct *current_task;
    struct cred *current_cred;

    if (is_inode_dir(old_dentry->d_inode))
        return 0;

    current_task = (struct task_struct *)bpf_get_current_task();
    current_cred = get_task_cred(current_task);

    ptr_prov_current_cred = get_or_create_cred_prov(current_cred);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_current_task = get_task_provenance(current_task, true);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov = get_or_create_inode_prov(old_dentry->d_inode);
    if (!ptr_prov) {
      return 0;
    }

    generates(RL_RENAME, current_task, ptr_prov_current_cred, ptr_prov_current_task, ptr_prov, NULL, 0);

    return 0;
}
#endif

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
#ifndef PROV_FILTER_INODE_SETATTR_OFF
SEC("lsm/inode_setattr")
int BPF_PROG(inode_setattr, struct dentry *dentry, struct iattr *attr) {
    union prov_elt *ptr_prov_current_cred, *ptr_prov_current_task, *ptr_prov_inode, *ptr_prov_iattr;
    struct task_struct *current_task;
    struct cred *current_cred;

    if (is_inode_dir(dentry->d_inode))
        return 0;

    current_task = (struct task_struct *)bpf_get_current_task();
    current_cred = get_task_cred(current_task);

    ptr_prov_current_cred = get_or_create_cred_prov(current_cred);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_current_task = get_task_provenance(current_task, true);
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

    generates(RL_SETATTR, current_task, ptr_prov_current_cred, ptr_prov_current_task, ptr_prov_iattr, NULL, 0);
    derives(RL_SETATTR_INODE, ptr_prov_iattr, ptr_prov_inode, NULL, 0);

    return 0;
}
#endif

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
#ifndef PROV_FILTER_INODE_GETATTR_OFF
SEC("lsm/inode_getattr")
int BPF_PROG(inode_getattr, const struct path *path) {
    union prov_elt *ptr_prov_current_cred, *ptr_prov_current_task, *ptr_prov_inode;
    struct task_struct *current_task;
    struct cred *current_cred;

    if (is_inode_dir(path->dentry->d_inode))
        return 0;

    current_task = (struct task_struct *)bpf_get_current_task();
    current_cred = get_task_cred(current_task);

    ptr_prov_current_cred = get_or_create_cred_prov(current_cred);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_current_task = get_task_provenance(current_task, true);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov_inode = get_or_create_inode_prov(path->dentry->d_inode);
    if (!ptr_prov_inode) {
      return 0;
    }

    uses(RL_GETATTR, current_task, ptr_prov_inode, ptr_prov_current_task, ptr_prov_current_cred, NULL, 0);

    return 0;
}
#endif

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
#ifndef PROV_FILTER_INODE_READLINK_OFF
SEC("lsm/inode_readlink")
int BPF_PROG(inode_readlink, struct dentry *dentry) {
    union prov_elt *ptr_prov_current_cred, *ptr_prov_current_task, *ptr_prov_inode;
    struct task_struct *current_task;
    struct cred *current_cred;

    if (is_inode_dir(dentry->d_inode))
        return 0;

    current_task = (struct task_struct *)bpf_get_current_task();
    current_cred = get_task_cred(current_task);

    ptr_prov_current_cred = get_or_create_cred_prov(current_cred);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_current_task = get_task_provenance(current_task, true);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov_inode = get_or_create_inode_prov(dentry->d_inode);
    if (!ptr_prov_inode) {
      return 0;
    }

    uses(RL_READ_LINK, current_task, ptr_prov_inode, ptr_prov_current_task, ptr_prov_current_cred, NULL, 0);

    return 0;
}
#endif

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
#ifndef PROV_FILTER_INODE_POST_SETXATTR_OFF
SEC("lsm/inode_post_setxattr")
int BPF_PROG(inode_post_setxattr, struct dentry *dentry, const char *name,const void *value, size_t size, int flags) {
    union prov_elt *ptr_prov_current_cred, *ptr_prov_current_task, *ptr_prov_inode;
    struct task_struct *current_task;
    struct cred *current_cred;

    if (is_inode_dir(dentry->d_inode))
        return 0;

    current_task = (struct task_struct *)bpf_get_current_task();
    current_cred = get_task_cred(current_task);

    ptr_prov_current_cred = get_or_create_cred_prov(current_cred);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_current_task = get_task_provenance(current_task, true);
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
#endif

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
#ifndef PROV_FILTER_INODE_GETXATTR_OFF
SEC("lsm/inode_getxattr")
int BPF_PROG(inode_getxattr, struct dentry *dentry, const char *name) {
    union prov_elt *ptr_prov_current_cred, *ptr_prov_current_task, *ptr_prov_inode;
    struct task_struct *current_task;
    struct cred *current_cred;

    if (is_inode_dir(dentry->d_inode))
        return 0;

    current_task = (struct task_struct *)bpf_get_current_task();
    current_cred = get_task_cred(current_task);

    ptr_prov_current_cred = get_or_create_cred_prov(current_cred);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_current_task = get_task_provenance(current_task, true);
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
#endif

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
#ifndef PROV_FILTER_INODE_LISTXATTR_OFF
SEC("lsm/inode_listxattr")
int BPF_PROG(inode_listxattr, struct dentry *dentry) {
    union prov_elt *ptr_prov_current_cred, *ptr_prov_current_task, *ptr_prov_inode;
    struct task_struct *current_task;
    struct cred *current_cred;

    if (is_inode_dir(dentry->d_inode))
        return 0;

    current_task = (struct task_struct *)bpf_get_current_task();
    current_cred = get_task_cred(current_task);

    ptr_prov_current_cred = get_or_create_cred_prov(current_cred);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_current_task = get_task_provenance(current_task, true);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov_inode = get_or_create_inode_prov(dentry->d_inode);
    if (!ptr_prov_inode) {
      return 0;
    }

    uses(RL_LSTXATTR, current_task, ptr_prov_inode, ptr_prov_current_task, ptr_prov_current_cred, NULL, 0);

    return 0;
}
#endif

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
#ifndef PROV_FILTER_INODE_REMOVEXATTR_OFF
SEC("lsm/inode_removexattr")
int BPF_PROG(inode_removexattr, struct dentry *dentry, const char *name) {
    union prov_elt *ptr_prov_current_cred, *ptr_prov_current_task, *ptr_prov_inode;
    struct task_struct *current_task;
    struct cred *current_cred;

    if (is_inode_dir(dentry->d_inode))
        return 0;

    current_task = (struct task_struct *)bpf_get_current_task();
    current_cred = get_task_cred(current_task);

    ptr_prov_current_cred = get_or_create_cred_prov(current_cred);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_current_task = get_task_provenance(current_task, true);
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
#endif

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
#ifndef PROV_FILTER_CRED_ALLOC_BLANK_OFF
SEC("lsm/cred_alloc_blank")
int BPF_PROG(cred_alloc_blank, struct cred *cred, gfp_t gfp) {
    /*union prov_elt *ptr_prov;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    struct cred *current_cred = get_task_cred(current_task);
    kuid_t current_cred_uid;
    kgid_t current_cred_gid;
    bpf_probe_read(&current_cred_uid, sizeof(current_cred_uid), &current_cred->uid);
    bpf_probe_read(&current_cred_gid, sizeof(current_cred_uid), &current_cred->gid);

    ptr_prov = (current_cred_uid.val == cred->uid.val && current_cred_gid.val == cred->gid.val) ? get_or_create_cred_prov(cred, current_task) : get_or_create_cred_prov(NULL, current_task);
    if (!ptr_prov) {
      return 0;
    }

    record_provenance(false, ptr_prov);
    */
    return 0;
}
#endif

/*!
 * @brief Record provenance when cred_free hook is triggered.
 *
 * This hook is triggered when deallocating and clearing the cred->security
 * field in a set of credentials. Record provenance relation RL_TERMINATE_PROC
 * by calling "record_terminate" function.
 * @param cred Points to the credentials to be freed.
 *
 */
#ifndef PROV_FILTER_CRED_FREE_OFF
SEC("lsm/cred_free")
int BPF_PROG(cred_free, struct cred *cred) {
    uint64_t key;
    union prov_elt *ptr_prov;

    ptr_prov = get_or_create_cred_prov(cred);
    if (!ptr_prov)
      return 0;
    // Record cred freed
    record_terminate(RL_TERMINATE_PROC, ptr_prov);
    key = get_key(cred);
    bpf_map_delete_elem(&cred_map, &key);
    return 0;
}
#endif

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
#ifndef PROV_FILTER_CRED_PREPARE_OFF
SEC("lsm/cred_prepare")
int BPF_PROG(cred_prepare, struct cred *new, const struct cred *old, gfp_t gfp) {
    union prov_elt *ptr_prov_new, *ptr_prov_old, *ptr_prov_task;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();

    ptr_prov_new = get_or_create_cred_prov(new);
    if (!ptr_prov_new)
      return 0;

    ptr_prov_old = get_or_create_cred_prov(old);
    if (!ptr_prov_old)
      return 0;

    ptr_prov_task = get_or_create_task_prov(current_task);
    if (!ptr_prov_task)
      return 0;

    generates(RL_CLONE_MEM, current_task, ptr_prov_old, ptr_prov_task, ptr_prov_new, NULL, 0);

    return 0;
}
#endif

#ifndef PROV_FILTER_PTRACE_ACCESS_CHECK_OFF
SEC("lsm/ptrace_access_check")
int BPF_PROG(ptrace_access_check, struct task_struct *child, unsigned int mode) {
    union prov_elt *ptr_prov_child, *ptr_prov_child_cred, *ptr_prov_current_task, *ptr_prov_current_cred;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    struct cred *current_cred, *child_cred;
    current_cred = get_task_cred(current_task);
    child_cred = get_task_cred(child);

    ptr_prov_child = get_or_create_task_prov(child);
    if (!ptr_prov_child) {
      return 0;
    }
    ptr_prov_child_cred = get_or_create_cred_prov(child_cred);
    if (!ptr_prov_child_cred) {
      return 0;
    }
    ptr_prov_current_task = get_task_provenance(current_task, false);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov_current_cred = get_or_create_cred_prov(current_cred);
    if (!ptr_prov_current_cred) {
      return 0;
    }

    if (mode & PTRACE_MODE_READ) {
      informs(RL_PTRACE_READ_TASK, ptr_prov_child, ptr_prov_current_task, NULL, mode);
      if (ptr_prov_child_cred != ptr_prov_current_cred) {
        uses(RL_PTRACE_READ, current_task, ptr_prov_child_cred, ptr_prov_current_task, ptr_prov_current_cred, NULL, 0);
      }
    }
    if (mode & PTRACE_MODE_ATTACH) {
      if (ptr_prov_child_cred != ptr_prov_current_cred) {
        generates(RL_PTRACE_ATTACH, current_task, ptr_prov_current_cred, ptr_prov_current_task, ptr_prov_child_cred, NULL, 0);
      }
      informs(RL_PTRACE_ATTACH_TASK, ptr_prov_current_task, ptr_prov_child, NULL, mode);
    }

    return 0;
}
#endif

#ifndef PROV_FILTER_PTRACE_TRACEME_OFF
SEC("lsm/ptrace_traceme")
int BPF_PROG(ptrace_traceme, struct task_struct *parent) {
    union prov_elt *ptr_prov, *ptr_prov_current;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();

    ptr_prov = get_or_create_task_prov(parent);
    if (!ptr_prov) {
      return 0;
    }
    ptr_prov_current = get_task_provenance(current_task, false);
    if (!ptr_prov_current) {
      return 0;
    }

    informs(RL_PTRACE_TRACEME, ptr_prov_current, ptr_prov, NULL, 0);
    return 0;
}
#endif

/*!
 * @brief Record provenance when mmap_file hook is triggered.
 *
 * This hook is triggered when checking permissions for a mmap operation.
 * The @file may be NULL, e.g., if mapping anonymous memory.
 * Provenance relation will not be recorded if:
 * 1. The file is NULL, or
 * 2. Failure occurred.
 * If the mmap is shared (flag: MAP_SHARED or MAP_SHARED_VALIDATE),
 * depending on the action allowed by the kernel,
 * record provenance relation RL_MMAP_WRITE and/or RL_MMAP_READ and/or
 * RL_MMAP_EXEC by calling "derives" function.
 * Information flows between the mmap file and calling process and its cred.
 * The direction of the information flow depends on the action allowed.
 * If the mmap is private (flag: MAP_PRIVATE),
 * we create an additional provenance node to represent the private mapped inode
 * by calling function "branch_mmap", record provenance relation RL_MMAP by
 * calling "derives" function because information flows from the original mapped
 * file to the private file.
 * Then depending on the action allowed by the kernel,
 * record provenance relation RL_MMAP_WRITE and/or RL_MMAP_READ and/or
 * RL_MMAP_EXEC by calling "derives" function.
 * Information flows between the new private mmap node and calling process and
 * its cred.
 * The direction of the information flow depends on the action allowed.
 * Note that this new node is short-lived.
 * @param file The file structure for file to map (may be NULL).
 * @param reqprot The protection requested by the application.
 * @param prot The protection that will be applied by the kernel.
 * @param flags The operational flags.
 * @return 0 if permission is granted and no error occurred; -ENOMEM if the
 * original file inode provenance entry is NULL; Other error codes inherited
 * from derives function.
 *
 */
#ifndef PROV_FILTER_MMAP_FILE_OFF
SEC("lsm/mmap_file")
int BPF_PROG(mmap_file, struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags) {
    union prov_elt *ptr_prov_current, *ptr_prov_current_cred, *ptr_prov_file_inode;
    struct task_struct *current_task;
    struct cred *current_cred;

    if (is_inode_dir(file->f_inode))
        return 0;

    current_task = (struct task_struct *)bpf_get_current_task_btf();
    current_cred = get_task_cred(current_task);

    if (__builtin_expect(!file, 0)) {
      return 0;
    }

    ptr_prov_current = get_task_provenance(current_task, true);
    if (!ptr_prov_current) {
      return 0;
    }
    ptr_prov_current_cred = get_or_create_cred_prov(current_cred);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_file_inode = get_or_create_inode_prov(file->f_inode);
    if (!ptr_prov_file_inode) {
      return 0;
    }

    if (provenance_is_opaque(ptr_prov_current_cred)) {
      return 0;
    }

    if ((flags & MAP_TYPE) == MAP_SHARED || (flags & MAP_TYPE) == MAP_SHARED_VALIDATE) {
      if ((prot & PROT_WRITE) != 0) {
        uses(RL_MMAP_WRITE, current_task, ptr_prov_file_inode, ptr_prov_current, ptr_prov_current_cred, file, flags);
      }
      if ((prot & PROT_READ) != 0) {
        uses(RL_MMAP_READ, current_task, ptr_prov_file_inode, ptr_prov_current, ptr_prov_current_cred, file, flags);
      }
      if ((prot & PROT_EXEC) != 0) {
        uses(RL_MMAP_EXEC, current_task, ptr_prov_file_inode, ptr_prov_current, ptr_prov_current_cred, file, flags);
      }
    } else {
      if ((prot & PROT_WRITE) != 0) {
        uses(RL_MMAP_WRITE_PRIVATE, current_task, ptr_prov_file_inode, ptr_prov_current, ptr_prov_current_cred, file, flags);
      }
      if ((prot & PROT_READ) != 0) {
        uses(RL_MMAP_READ_PRIVATE, current_task, ptr_prov_file_inode, ptr_prov_current, ptr_prov_current_cred, file, flags);
      }
      if ((prot & PROT_EXEC) != 0) {
        uses(RL_MMAP_EXEC_PRIVATE, current_task, ptr_prov_file_inode, ptr_prov_current, ptr_prov_current_cred, file, flags);
      }
    }

    return 0;
}
#endif

#ifdef CONFIG_SECURITY_FLOW_FRIENDLY
/*!
 * @brief Record provenance when mmap_munmap hook is triggered.
 *
 * This hook is triggered when a file is unmmap'ed.
 * We obtain the provenance entry of the mmap'ed file, and if it shows that the
 * mmap'ed file is shared based on the flags,
 * record provenance relation RL_MUNMAP by calling "derives" function.
 * Information flows from cred of the process that unmmaps the file to the
 * mmap'ed file.
 * Note that if the file to be unmmap'ed is private, the provenance of the
 * mmap'ed file is short-lived and thus no longer exists.
 * @param mm Unused parameter.
 * @param vma Virtual memory of the calling process.
 * @param start Unused parameter.
 * @param end Unused parameter.
 *
 */
#ifndef PROV_FILTER_MMAP_MUNMAP_OFF
SEC("lsm/mmap_munmap")
int BPF_PROG(mmap_munmap, struct mm_struct *mm, struct vm_area_struct *vma, unsigned long start, unsigned long end) {
    union prov_elt *ptr_prov_current, *ptr_prov_current_cred, *ptr_prov_inode;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    struct cred *current_cred;
    current_cred = get_task_cred(current_task);
    struct file *mmapf;
    vm_flags_t flags = vma->vm_flags;

    ptr_prov_current = get_task_provenance(current_task, true);
    if (!ptr_prov_current) {
      return 0;
    }
    ptr_prov_current_cred = get_or_create_cred_prov(current_cred);
    if (!ptr_prov_current_cred) {
      return 0;
    }

    if (vm_mayshare(flags)) {
      mmapf = vma->vm_file;
      if (mmapf) {
        ptr_prov_inode = get_or_create_inode_prov(mmapf->f_inode);
        if (!ptr_prov_inode) {
          return 0;
        }
        generates(RL_MUNMAP, current_task, ptr_prov_current_cred, ptr_prov_current, ptr_prov_inode, mmapf, flags);
      }
    }

    return 0;
}
#endif
#endif

 /*!
  * @brief Record provenance when file_permission hook is triggered.
  *
  * This hook is triggered when checking file permissions before accessing an
  * open file.
  * This hook is called by various operations that read or write files.
  * A security module can use this hook to perform additional checking on these
  * operations,
  * e.g., to revalidate permissions on use to support privilege bracketing or
  * policy changes.
  * Notice that this hook is used when the actual read/write operations are
  * performed, whereas the inode_security_ops hook is called when a file is
  * opened (as well as many other operations).
  * Caveat:
  * Although this hook can be used to revalidate permissions for various system
  * call operations that read or write files,
  * it does not address the revalidation of permissions for memory-mapped files.
  * Security modules must handle this separately if they need such revalidation.
  * Depending on the type of the @file (e.g., a regular file or a directory),
  * and the requested permission from @mask,
  * record various provenance relations, including:
  * RL_WRITE, RL_READ, RL_SEARCH, RL_SND, RL_RCV, RL_EXEC.
  * @param file The file structure being accessed.
  * @param mask The requested permissions.
  * @return 0 if permission is granted; -ENOMEM if inode provenance is NULL.
  * Other error codes unknown.
  *
  */
#ifndef PROV_FILTER_FILE_PERMISSION_OFF
SEC("lsm/file_permission")
int BPF_PROG(file_permission, struct file *file, int mask) {
    union prov_elt *ptr_prov_current_task, *ptr_prov_current_cred, *ptr_prov_file_inode;
    struct task_struct *current_task;
    struct cred *current_cred;

    if (is_inode_dir(file->f_inode))
        return 0;

    current_task = (struct task_struct *)bpf_get_current_task();
    current_cred = get_task_cred(current_task);

    uint32_t perms = file_mask_to_perms((file->f_inode)->i_mode, mask);

    ptr_prov_current_task = get_task_provenance(current_task, true);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov_current_cred = get_or_create_cred_prov(current_cred);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_file_inode = get_or_create_inode_prov(file->f_inode);
    if (!ptr_prov_file_inode) {
      return 0;
    }

    if (is_inode_socket(file->f_inode)) {
      if ((perms & (FILE__WRITE | FILE__APPEND)) != 0) {
        generates(RL_SND, current_task, ptr_prov_current_cred, ptr_prov_current_task, ptr_prov_file_inode, file, mask);
      }
      if ((perms & (FILE__READ)) != 0) {
        uses(RL_RCV, current_task, ptr_prov_file_inode, ptr_prov_current_task, ptr_prov_current_cred, file, mask);
      }
    } else {
      if ((perms & (FILE__WRITE | FILE__APPEND)) != 0) {
        generates(RL_WRITE, current_task, ptr_prov_current_cred, ptr_prov_current_task, ptr_prov_file_inode, file, mask);
      }
      if ((perms & (FILE__READ)) != 0) {
        uses(RL_READ, current_task, ptr_prov_file_inode, ptr_prov_current_task, ptr_prov_current_cred, file, mask);
      }
      if ((perms & (FILE__EXECUTE)) != 0) {
        if (provenance_is_opaque(ptr_prov_file_inode)) {
          set_opaque(ptr_prov_current_cred);
        } else {
          derives(RL_EXEC, ptr_prov_file_inode, ptr_prov_current_cred, file, mask);
        }
      }
    }

    return 0;
}
#endif

#ifdef CONFIG_SECURITY_FLOW_FRIENDLY
/*!
 * @brief Record provenance when file_splice_pipe_to_pipe hook is triggered
 * (splice system call).
 *
 * Record provenance relation RL_SPLICE by calling "derives" function.
 * Information flows from one pipe @in to another pipe @out.
 * Fail if either file inode provenance does not exist.
 * @param in Information source file.
 * @param out Information drain file.
 * @return 0 if no error occurred; -ENOMEM if either end of the file provenance
 * entry is NULL; Other error code inherited from derives function.
 *
 */
#ifndef PROV_FILTER_FILE_SPLICE_PIPE_TO_PIPE_OFF
SEC("lsm/file_splice_pipe_to_pipe")
int BPF_PROG(file_splice_pipe_to_pipe, struct file *in, struct file *out) {
    union prov_elt *ptr_prov_current_task, *ptr_prov_current_cred, *ptr_prov_in_inode, *ptr_prov_out_inode;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    struct cred *current_cred;
    current_cred = get_task_cred(current_task);

    ptr_prov_current_task = get_task_provenance(current_task, true);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov_current_cred = get_or_create_cred_prov(current_cred);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_in_inode = get_or_create_inode_prov(in->f_inode);
    if (!ptr_prov_in_inode) {
      return 0;
    }
    ptr_prov_out_inode = get_or_create_inode_prov(out->f_inode);
    if (!ptr_prov_out_inode) {
      return 0;
    }

    uses(RL_SPLICE_IN, current_task, ptr_prov_in_inode, ptr_prov_current_task, ptr_prov_current_cred, NULL, 0);
    generates(RL_SPLICE_OUT, current_task, ptr_prov_current_cred, ptr_prov_current_task, ptr_prov_out_inode, NULL, 0);

    return 0;
}
#endif
#endif

/*!
 * @brief Record provenance when file_open hook is triggered.
 *
 * This hook is triggered when saving open-time permission checking state for
 * later use upon file_permission,
 * and rechecking access if anything has changed since inode_permission.
 * Record provenance relation RL_OPEN by calling "uses" function.
 * Information flows from inode of the file to be opened to the calling process,
 * and eventually to its cred.
 * @param file The file to be opened.
 * @param cred Unused parameter.
 * @return 0 if no error occurred; -ENOMEM if the file inode provenance entry is
 * NULL; other error code inherited from uses function.
 *
 */
#ifndef PROV_FILTER_FILE_OPEN_OFF
SEC("lsm/file_open")
int BPF_PROG(file_open, struct file *file) {
    union prov_elt *ptr_prov_current_task, *ptr_prov_current_cred, *ptr_prov_file_inode;
    struct task_struct *current_task;
    struct cred *current_cred;

    if (is_inode_dir(file->f_inode))
        return 0;

    current_task = (struct task_struct *)bpf_get_current_task_btf();

    current_cred = get_task_cred(current_task);

    ptr_prov_current_task = get_task_provenance(current_task, true);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov_current_cred = get_or_create_cred_prov(current_cred);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_file_inode = get_or_create_inode_prov(file->f_inode);
    if (!ptr_prov_file_inode) {
      return 0;
    }

    uses(RL_OPEN, current_task, ptr_prov_file_inode, ptr_prov_current_task, ptr_prov_current_cred, file, 0);

    return 0;
}
#endif

/*!
 * @brief Record provenance when file_receive hook is triggered.
 *
 * This hook allows security modules to control the ability of a process to
 * receive an open file descriptor via socket IPC.
 * Record provenance relation RL_FILE_RCV by calling "uses" function.
 * Information flows from inode of the file being received to the calling
 * process, and eventually to its cred.
 * @param file The file structure being received.
 * @return 0 if permission is granted, no error occurred; -ENOMEM if the
 * file inode provenance entry is NULL; Other error code inherited from uses
 * function.
 *
 */
#ifndef PROV_FILTER_FILE_RECEIVE_OFF
SEC("lsm/file_receive")
int BPF_PROG(file_receive, struct file *file) {
    union prov_elt *ptr_prov_current_task, *ptr_prov_current_cred, *ptr_prov_file_inode;
    struct task_struct *current_task;
    struct cred *current_cred;

    if (is_inode_dir(file->f_inode))
        return 0;

    current_task = (struct task_struct *)bpf_get_current_task_btf();
    current_cred = get_task_cred(current_task);

    ptr_prov_current_task = get_task_provenance(current_task, true);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov_current_cred = get_or_create_cred_prov(current_cred);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_file_inode = get_or_create_inode_prov(file->f_inode);
    if (!ptr_prov_file_inode) {
      return 0;
    }

    uses(RL_FILE_RCV, current_task, ptr_prov_file_inode, ptr_prov_current_task, ptr_prov_current_cred, file, 0);

    return 0;
}
#endif

/*
 *	Check permission before performing file locking operations.
 *	Note: this hook mediates both flock and fcntl style locks.
 *	@file contains the file structure.
 *	@cmd contains the posix-translated lock operation to perform
 *	(e.g. F_RDLCK, F_WRLCK).
 *	Return 0 if permission is granted.
 */
#ifndef PROV_FILTER_FILE_LOCK_OFF
SEC("lsm/file_lock")
int BPF_PROG(file_lock, struct file *file, unsigned int cmd) {
    union prov_elt *ptr_prov_current_task, *ptr_prov_current_cred, *ptr_prov_file_inode;
    struct task_struct *current_task;
    struct cred *current_cred;

    if (is_inode_dir(file->f_inode))
        return 0;

    current_task = (struct task_struct *)bpf_get_current_task_btf();
    current_cred = get_task_cred(current_task);

    ptr_prov_current_task = get_task_provenance(current_task, true);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov_current_cred = get_or_create_cred_prov(current_cred);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_file_inode = get_or_create_inode_prov(file->f_inode);
    if (!ptr_prov_file_inode) {
      return 0;
    }

    generates(RL_FILE_LOCK, current_task, ptr_prov_current_cred, ptr_prov_current_task, ptr_prov_file_inode, file, cmd);

    return 0;
}
#endif

/*!
 * @brief Record provenance when file_ioctl hook is triggered.
 *
 * This hook is triggered when checking permission for an ioctl operation on
 * @file.
 * Note that @arg sometimes represents a user space pointer; in other cases, it
 * may be a simple integer value.
 * When @arg represents a user space pointer, it should never be used by the
 * security module.
 * Record provenance relation RL_WRITE_IOCTL by calling "generates" function
 * and RL_READ_IOCTL by calling "uses" function.
 * Information flows between the file and the calling process and its cred.
 * At the end, we save @iprov provenance.
 * @param file The file structure.
 * @param cmd The operation to perform.
 * @param arg The operational arguments.
 * @return 0 if permission is granted or no error occurred; -ENOMEM if the file
 * inode provenance entry is NULL; Other error code inherited from
 * generates/uses function.
 *
 */
#ifndef PROV_FILTER_FILE_IOCTL_OFF
SEC("lsm/file_ioctl")
int BPF_PROG(file_ioctl, struct file *file, unsigned int cmd, unsigned long arg) {
    union prov_elt *ptr_prov_current_task, *ptr_prov_current_cred, *ptr_prov_file_inode;
    struct task_struct *current_task;
    struct cred *current_cred;

    if (is_inode_dir(file->f_inode))
        return 0;

    current_task = (struct task_struct *)bpf_get_current_task_btf();
    current_cred = get_task_cred(current_task);

    ptr_prov_current_task = get_task_provenance(current_task, true);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov_current_cred = get_or_create_cred_prov(current_cred);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_file_inode = get_or_create_inode_prov(file->f_inode);
    if (!ptr_prov_file_inode) {
      return 0;
    }

    generates(RL_WRITE_IOCTL, current_task, ptr_prov_current_cred, ptr_prov_current_task, ptr_prov_file_inode, NULL, 0);
    uses(RL_READ_IOCTL, current_task, ptr_prov_file_inode, ptr_prov_current_task, ptr_prov_current_cred, NULL, 0);

    return 0;
}
#endif

SEC("lsm/file_send_sigiotask")
int BPF_PROG(file_send_sigiotask, struct task_struct *task, struct fown_struct *fown, int signum) {
    struct file *file = container_of(fown, struct file, f_owner);

    struct inode *inode;
    bpf_probe_read(&inode, sizeof(inode), &file->f_inode);

    union prov_elt *ptr_prov_task, *ptr_prov_cred, *ptr_prov_inode;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();

    ptr_prov_task = get_or_create_task_prov(task);
    if (!ptr_prov_task) {
      return 0;
    }
    ptr_prov_cred = get_or_create_cred_prov(task->cred);
    if (!ptr_prov_cred) {
      return 0;
    }
    ptr_prov_inode = get_or_create_inode_prov(inode);
    if (!ptr_prov_inode) {
      return 0;
    }

    if (!signum) {
      signum = SIGIO;
    }

    uses(RL_FILE_SIGIO, current_task, ptr_prov_inode, ptr_prov_task, ptr_prov_cred, file, signum);

    return 0;
}

/*!
 * @brief Record provenance when msg_msg_alloc_security hook is triggered.
 *
 * This hooks allocates and attaches a security structure to the msg->security
 * field.
 * The security field is initialized to NULL when the structure is first
 * created.
 * This function initializes and attaches a new provenance entry to the
 * msg->provenance field.
 * We create a new provenance node ENT_MSG and update the information in the
 * provenance entry from @msg.
 * Record provenance relation RL_MSG_CREATE by calling "generates" function.
 * Information flows from cred of the calling process to the task, and
 * eventually to the newly created msg node.
 * @param msg The message structure to be modified.
 * @return 0 if operation was successful and permission is granted; -ENOMEM if
 * no memory can be allocated for the new provenance entry; other error codes
 * inherited from generates function.
 *
 */
#ifndef PROV_FILTER_MSG_MSG_ALLOC_SECURITY_OFF
SEC("lsm/msg_msg_alloc_security")
int BPF_PROG(msg_msg_alloc_security, struct msg_msg *msg) {
    union prov_elt *ptr_prov_current_task, *ptr_prov_current_cred, *ptr_prov_msg;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    struct cred *current_cred;
    current_cred = get_task_cred(current_task);

    ptr_prov_current_task = get_task_provenance(current_task, true);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov_current_cred = get_or_create_cred_prov(current_cred);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_msg = get_or_create_msg_msg_prov(msg);
    if (!ptr_prov_msg) {
      return 0;
    }

    generates(RL_MSG_CREATE, current_task, ptr_prov_current_cred, ptr_prov_current_task, ptr_prov_msg, NULL, 0);

    return 0;
}
#endif

/*!
 * @brief Record provenance when msg_msg_free_security hook is triggered.
 *
 * This hook is triggered when deallocating the security structure for this
 * message.
 * Free msg provenance entry when security structure for this message is
 * deallocated.
 * If the msg has a valid provenance entry pointer (i.e., non-NULL), free the
 * memory and set the pointer to NULL.
 * @param msg The message structure whose security structure to be freed.
 *
 */
#ifndef PROV_FILTER_MSG_MSG_FREE_SECURITY_OFF
SEC("lsm/msg_msg_free_security")
int BPF_PROG(msg_msg_free_security, struct msg_msg *msg) {
    uint64_t key = get_key(msg);
    union prov_elt *ptr_prov_msg;

    ptr_prov_msg = get_or_create_msg_msg_prov(msg);
    if (!ptr_prov_msg) {
      return 0;
    }

    record_terminate(RL_FREED, ptr_prov_msg);

    bpf_map_delete_elem(&msg_msg_map, &key);
    return 0;
}
#endif

/*!
 * @brief Helper function for two security hooks: msg_queue_msgsnd and
 * mq_timedsend.
 *
 * Record provenance relation RL_SND_MSG_Q by calling "generates" function.
 * Information flows from calling process's cred to the process, and eventually
 * to msg.
 * @param msg The message structure.
 * @return 0 if no error occurred; Other error codes inherited from generates
 * function.
 *
 */
static inline int __mq_msgsnd(struct msg_msg *msg) {
    union prov_elt *ptr_prov_current_task, *ptr_prov_current_cred, *ptr_prov_msg;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    struct cred *current_cred;
    current_cred = get_task_cred(current_task);

    ptr_prov_current_task = get_task_provenance(current_task, true);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov_current_cred = get_or_create_cred_prov(current_cred);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_msg = get_or_create_msg_msg_prov(msg);
    if (!ptr_prov_msg) {
      return 0;
    }

    generates(RL_SND_MSG_Q, current_task, ptr_prov_current_cred, ptr_prov_current_task, ptr_prov_msg, NULL, 0);

    return 0;
}

/*!
 * @brief Record provenance when msg_queue_msgsnd hook is triggered.
 *
 * This hook is trigger when checking permission before a message, @msg,
 * is enqueued on the message queue, @msq.
 * This function simply calls the helper function __mq_msgsnd.
 * @param msq The message queue to send message to.
 * @param msg The message to be enqueued.
 * @param msqflg The operational flags.
 * @return 0 if permission is granted. Other error codes inherited from
 * __mq_msgsnd function.
 *
 */
#ifndef PROV_FILTER_MSG_QUEUE_MSGSND_OFF
SEC("lsm/msg_queue_msgsnd")
int BPF_PROG(msg_queue_msgsnd, struct kern_ipc_perm *msq, struct msg_msg *msg, int msqflg) {
    return __mq_msgsnd(msg);
}
#endif

/*!
 * @brief Record provenance when mq_timedsend hook is triggered.
 *
 * This function simply calls the helper function __mq_msgsnd.
 * @param inode Unused parameter.
 * @param msg The message to be enqueued.
 * @param ts Unused parameter.
 * @return 0 if permission is granted. Other error codes inherited from
 * __mq_msgsnd function.
 *
 */
#ifdef CONFIG_SECURITY_FLOW_FRIENDLY
#ifndef PROV_FILTER_MQ_TIMEDSEND_OFF
SEC("lsm/mq_timedsend")
int BPF_PROG(mq_timedsend, struct inode *inode, struct msg_msg *msg, struct timespec64 *ts) {
    return __mq_msgsnd(msg);
}
#endif
#endif

/*!
 * @brief Helper function for two security hooks: msg_queue_msgrcv and
 * mq_timedreceive.
 *
 * Record provenance relation RL_RCV_MSG_Q by calling "uses" function.
 * Information flows from msg to the calling process, and eventually to its
 * cred.
 * @param cprov The calling process's cred provenance entry pointer.
 * @param msg The message structure.
 * @return 0 if no error occurred; Other error codes inherited from uses
 * function.
 *
 */
static inline int __mq_msgrcv(union prov_elt *ptr_prov_cred, struct msg_msg *msg) {
    union prov_elt *ptr_prov_msg, *ptr_prov_current_task;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();

    ptr_prov_current_task = get_task_provenance(current_task, true);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov_msg = get_or_create_msg_msg_prov(msg);
    if (!ptr_prov_msg) {
      return 0;
    }

    uses(RL_RCV_MSG_Q, current_task, ptr_prov_msg, ptr_prov_current_task, ptr_prov_cred, NULL, 0);

    return 0;
}

/*!
 * @brief Record provenance when msg_queue_msgrcv hook is triggered.
 *
 * This hook is triggered when checking permission before a message, @msg, is
 * removed from the message queue, @msq.
 * The @target task structure contains a pointer to the process that will be
 * receiving the message (not equal to the current process when inline receives
 * are being performed).
 * Since it is the receiving task that receives the msg,
 * we first obtain the receiving task's cred provenance entry pointer,
 * and then simply calls the helper function __mq_msgrcv to record the
 * information flow.
 * @param msq The message queue to retrieve message from.
 * @param msg The message destination.
 * @param target The task structure for recipient process.
 * @param type The type of message requested.
 * @param mode The operational flags.
 * @return 0 if permission is granted. Other error codes inherited from
 * __mq_msgrcv function.
 *
 */
#ifndef PROV_FILTER_MSG_QUEUE_MSGRCV_OFF
SEC("lsm/msg_queue_msgrcv")
int BPF_PROG(msg_queue_msgrcv, struct kern_ipc_perm *msq, struct msg_msg *msg, struct task_struct *target, long type, int mode) {
    struct cred* cred = get_task_cred(target);
    union prov_elt *ptr_prov_cred;

    ptr_prov_cred = get_or_create_cred_prov(cred);
    if (!ptr_prov_cred)
      return 0;

    return __mq_msgrcv(ptr_prov_cred, msg);
}
#endif

/*!
 * @brief Record provenance when mq_timedreceive hook is triggered.
 *
 * Current process will be receiving the message.
 * We simply calls the helper function __mq_msgrcv to record the information
 * flow.
 * @param inode Unused parameter.
 * @param msg The message destination.
 * @param ts Unused parameter.
 * @return 0 if permission is granted. Other error codes inherited from
 * __mq_msgrcv function.
 *
 */
#ifdef CONFIG_SECURITY_FLOW_FRIENDLY
#ifndef PROV_FILTER_MQ_TIMEDRECEIVE_OFF
SEC("lsm/mq_timedreceive")
int BPF_PROG(mq_timedreceive, struct inode *inode, struct msg_msg *msg, struct timespec64 *ts) {
    union prov_elt *ptr_prov_current_cred;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    struct cred *current_cred;
    current_cred = get_task_cred(current_task);

    ptr_prov_current_cred = get_or_create_cred_prov(current_cred);
    if (!ptr_prov_current_cred) {
      return 0;
    }

    return __mq_msgrcv(ptr_prov_current_cred, msg);
}
#endif
#endif

/*!
 * @brief Record provenance when shm_alloc_security hook is triggered.
 *
 * This hunk is triggered when allocating and attaching a security structure to
 * the shp->shm_perm.security field.
 * The security field is initialized to NULL when the structure is first
 * created.
 * This function allocates and attaches a provenance entry to the
 * shp->shm_perm.provenance field.
 * That is, it creates a new provenance node ENT_SHM.
 * It also fills in some provenance information based on the information
 * contained in @shp.
 * Record provenance relation RL_SH_CREATE_READ by calling "uses" function.
 * For read, information flows from shared memory to the calling process, and
 * eventually to its cred.
 * Record provenance relation RL_SH_CREATE_WRITE by calling "uses" function.
 * For write, information flows from the calling process's cree to the process,
 * and eventually to shared memory.
 * @param shp The shared memory structure to be modified.
 * @return 0 if operation was successful and permission is granted, no error
 * occurred. -ENOMEM if no memory can be allocated to create a new ENT_SHM
 * provenance entry. Other error code inherited from uses and generates function
 *.
 *
 */
#ifndef PROV_FILTER_SHM_ALLOC_SECURITY_OFF
SEC("lsm/shm_alloc_security")
int BPF_PROG(shm_alloc_security, struct kern_ipc_perm *shp) {
    union prov_elt *ptr_prov_current_task, *ptr_prov_current_cred, *ptr_prov_shp;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    struct cred *current_cred;
    current_cred = get_task_cred(current_task);

    ptr_prov_current_task = get_task_provenance(current_task, true);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov_current_cred = get_or_create_cred_prov(current_cred);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_shp = get_or_create_kern_ipc_perm_prov(shp);
    if (!ptr_prov_shp) {
      return 0;
    }

    generates(RL_SH_CREATE_READ, current_task, ptr_prov_current_cred, ptr_prov_current_task, ptr_prov_shp, NULL, 0);
    generates(RL_SH_CREATE_WRITE, current_task, ptr_prov_current_cred, ptr_prov_current_task, ptr_prov_shp, NULL, 0);

    return 0;
}
#endif

/*!
 * @brief Record provenance when shm_free_security hook is triggered.
 *
 * This hook is triggered when deallocating the security struct for this memory
 * segment.
 * We simply free the memory of the allocated provenance entry if it exists, and
 * set the pointer to NULL.
 * @param shp The shared memory structure to be modified.
 *
 */
#ifndef PROV_FILTER_SHM_FREE_SECURITY_OFF
SEC("lsm/shm_free_security")
int BPF_PROG(shm_free_security, struct kern_ipc_perm *shp) {
    uint64_t key = get_key(shp);
    union prov_elt *ptr_prov_shp;

    ptr_prov_shp = get_or_create_kern_ipc_perm_prov(shp);
    if (!ptr_prov_shp) {
      return 0;
    }

    record_terminate(RL_FREED, ptr_prov_shp);
    bpf_map_delete_elem(&kern_ipc_perm_map, &key);

    return 0;
}
#endif

/*!
 * @brief Record provenance when shm_shmat hook is triggered.
 *
 * This hook is triggered when checking permissions prior to allowing the shmat
 * system call to attach the
 * shared memory segment @shp to the data segment of the calling process.
 * The attaching address is specified by @shmaddr.
 * If @shmflg is SHM_RDONLY (readable only), then:
 * Record provenance relation RL_SH_ATTACH_READ by calling "uses" function.
 * Information flows from shared memory to the calling process, and then
 * eventually to its cred.
 * Otherwise, shared memory is both readable and writable, then:
 * Record provenance relation RL_SH_ATTACH_READ by calling "uses" function and
 * RL_SH_ATTACH_WRITE by calling "uses" function.
 * Information can flow both ways.
 * @param shp The shared memory structure to be modified.
 * @param shmaddr The address to attach memory region to.
 * @param shmflg The operational flags.
 * @return 0 if permission is granted and no error occurred; -ENOMEM if shared
 * memory provenance entry does not exist. Other error codes inherited from uses
 * and generates function.
 *
 */
#ifndef PROV_FILTER_SHM_SHMAT_OFF
SEC("lsm/shm_shmat")
int BPF_PROG(shm_shmat, struct kern_ipc_perm *shp, char *shmaddr, int shmflg) {
    union prov_elt *ptr_prov_current_task, *ptr_prov_current_cred, *ptr_prov_shp;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    struct cred *current_cred;
    current_cred = get_task_cred(current_task);

    ptr_prov_current_task = get_task_provenance(current_task, true);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov_current_cred = get_or_create_cred_prov(current_cred);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_shp = get_or_create_kern_ipc_perm_prov(shp);
    if (!ptr_prov_shp) {
      return 0;
    }

    if (shmflg & SHM_RDONLY) {
      uses(RL_SH_ATTACH_READ, current_task, ptr_prov_shp, ptr_prov_current_task, ptr_prov_current_cred, NULL, shmflg);
    } else {
      uses(RL_SH_ATTACH_READ, current_task, ptr_prov_shp, ptr_prov_current_task, ptr_prov_current_cred, NULL, shmflg);
      generates(RL_SH_ATTACH_WRITE, current_task, ptr_prov_current_cred, ptr_prov_current_task, ptr_prov_shp, NULL, shmflg);
    }

    return 0;
}
#endif

#ifdef CONFIG_SECURITY_FLOW_FRIENDLY
/*!
 * @brief Record provenance when shm_shmdt hook is triggered.
 *
 * This hook is triggered when detaching the shared memory segment from the
 * address space of the calling process.
 * The to-be-detached segment must be currently attached with shmaddr equal to
 * the value returned by the attaching shmat() call.
 * Record provenance relation RL_SHMDT by calling "generates" function.
 * Information flows from the calling process's cred to the process, and
 * eventually to the shared memory.
 * @param shp The shared memory structure to be modified.
 *
 */
#ifndef PROV_FILTER_SHM_SHMDT_OFF
SEC("lsm/shm_shmdt")
int BPF_PROG(shm_shmdt, struct kern_ipc_perm *shp) {
    union prov_elt *ptr_prov_current_task, *ptr_prov_current_cred, *ptr_prov_shp;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    struct cred *current_cred;
    current_cred = get_task_cred(current_task);

    ptr_prov_current_task = get_task_provenance(current_task, true);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov_current_cred = get_or_create_cred_prov(current_cred);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_shp = get_or_create_kern_ipc_perm_prov(shp);
    if (!ptr_prov_shp) {
      return 0;
    }

    generates(RL_SHMDT, current_task, ptr_prov_current_cred, ptr_prov_current_task, ptr_prov_shp, NULL, 0);

    return 0;
}
#endif
#endif

/*!
 * @brief Record provenance when socket_post_create hook is triggered.
 *
 * This hook allows a module to update or allocate a per-socket security
 * structure.
 * Note that the security field was not added directly to the socket structure,
 * but rather, the socket security information is stored in the associated
 * inode.
 * Typically, the inode alloc_security hook will allocate and and attach
 * security information to sock->inode->i_security.
 * This hook may be used to update the sock->inode->i_security field
 * with additional information that wasn't available when the inode was
 * allocated.
 * Record provenance relation RL_SOCKET_CREATE by calling "generates" function.
 * Information flows from the calling process's cred to the process, and
 * eventually to the socket that is being created.
 * If @kern is 1 (kernal socket), no provenance relation is recorded.
 * This is becasuse kernel socket is a form of communication between kernel and
 * userspace.
 * We do not capture kernel's provenance for now.
 * @param sock The newly created socket structure.
 * @param family The requested protocol family.
 * @param type The requested communications type.
 * @param protocol The requested protocol.
 * @param kern Set to 1 if it is a kernel socket.
 * @return 0 if no error occurred; -ENOMEM if inode provenance entry does not
 * exist. Other error codes inherited from generates function.
 *
 * @todo Maybe support kernel socket in a future release.
 */
#ifndef PROV_FILTER_SOCKET_POST_CREATE_OFF
SEC("lsm/socket_post_create")
int BPF_PROG(socket_post_create, struct socket *sock, int family, int type, int protocol, int kern) {
    union prov_elt *ptr_prov_current_task, *ptr_prov_current_cred, *ptr_prov_sock_inode;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    struct cred *current_cred;
    current_cred = get_task_cred(current_task);

    if (kern) {
      return 0;
    }

    ptr_prov_current_task = get_task_provenance(current_task, true);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov_current_cred = get_or_create_cred_prov(current_cred);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_sock_inode = get_or_create_inode_prov((struct inode *)bpf_inode_from_sock(sock));
    if (!ptr_prov_sock_inode) {
      return 0;
    }

    generates(RL_SOCKET_CREATE, current_task, ptr_prov_current_cred, ptr_prov_current_task, ptr_prov_sock_inode, NULL, 0);

    return 0;
}
#endif

/*!
 * @brief Record provenance when socket_bind hook is triggered.
 *
 * This hook is triggered when checking permission before socket protocol layer
 * bind operation is performed, and the socket @sock is bound to the address
 * specified in the @address parameter.
 * The function records the provenance relations if the calling process is not
 * set to be opaque (i.e., should be recorded).
 * The relation between the socket and its address is recorded first,
 * then record provenance relation RL_BIND by calling "generates" function.
 * Information flows from the cred of the calling process to the process itself,
 * and eventually to the socket.
 * If the address family is PF_INET (we only support IPv4 for now), we check if
 * we should record the packet from the socket,
 * and track and propagate recording from the socket and the calling process.
 * Note that usually server binds the socket to its local address.
 * @param sock The socket structure.
 * @param address The address to bind to.
 * @param addrlen The length of address.
 * @return 0 if permission is granted and no error occurred; -EINVAL if socket
 * address is longer than @addrlen; -ENOMEM if socket inode provenance entry
 * does not exist. Other error codes inherited.
 *
 */
#ifndef PROV_FILTER_SOCKET_BIND_OFF
SEC("lsm/socket_bind")
int BPF_PROG(socket_bind, struct socket *sock, struct sockaddr *address, int addrlen) {
    union prov_elt *ptr_prov_current_task, *ptr_prov_current_cred, *ptr_prov_sock_inode;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    struct cred *current_cred;
    current_cred = get_task_cred(current_task);

    ptr_prov_current_task = get_task_provenance(current_task, true);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov_current_cred = get_or_create_cred_prov(current_cred);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_sock_inode = get_or_create_inode_prov((struct inode *)bpf_inode_from_sock(sock));
    if (!ptr_prov_sock_inode) {
      return 0;
    }

    if (provenance_is_opaque(ptr_prov_current_cred)) {
      return 0;
    }

    record_address(address, addrlen, ptr_prov_sock_inode);

    generates(RL_BIND, current_task, ptr_prov_current_cred, ptr_prov_current_task, ptr_prov_sock_inode, NULL, 0);

    return 0;
}
#endif

/*!
 * @brief Record provenance when socket_connect hook is triggered.
 *
 * This hook is triggered when checking permission before socket protocol layer
 * connect operation attempts to connect socket @sock to a remote address,
 * @address.
 * This function is similar to the above provenance_socket_bind function, except
 * that we record provenance relation RL_CONNECT by calling "generates"
 * function.
 * @param sock The socket structure.
 * @param address The address of remote endpoint.
 * @param addrlen The length of address.
 * @return 0 if permission is granted and no error occurred; -EINVAL if socket
 * address is longer than @addrlen; -ENOMEM if socket inode provenance entry
 * does not exist. Other error codes inherited.
 *
 */
#ifndef PROV_FILTER_SOCKET_CONNECT_OFF
SEC("lsm/socket_connect")
int BPF_PROG(socket_connect, struct socket *sock, struct sockaddr *address, int addrlen) {
    union prov_elt *ptr_prov_current_task, *ptr_prov_current_cred, *ptr_prov_sock_inode;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    struct cred *current_cred;
    current_cred = get_task_cred(current_task);

    ptr_prov_current_task = get_task_provenance(current_task, true);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov_current_cred = get_or_create_cred_prov(current_cred);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_sock_inode = get_or_create_inode_prov((struct inode *)bpf_inode_from_sock(sock));
    if (!ptr_prov_sock_inode) {
      return 0;
    }

    if (provenance_is_opaque(ptr_prov_current_cred)) {
      return 0;
    }

    record_address(address, addrlen, ptr_prov_sock_inode);

    generates(RL_CONNECT, current_task, ptr_prov_current_cred, ptr_prov_current_task, ptr_prov_sock_inode, NULL, 0);

    return 0;
}
#endif

/*!
 * @brief Record provenance when socket_listen hook is triggered.
 *
 * This hook is triggered when checking permission before socket protocol layer
 * listen operation.
 * Record provenance relation RL_LISTEN by calling "generates" function.
 * @param sock The socket structure.
 * @param backlog The maximum length for the pending connection queue.
 * @return 0 if no error occurred; -ENOMEM if socket inode provenance entry does
 * not exist. Other error codes inherited from generates function.
 *
 */
#ifndef PROV_FILTER_SOCKET_LISTEN_OFF
SEC("lsm/socket_listen")
int BPF_PROG(socket_listen, struct socket *sock, int backlog) {
    union prov_elt *ptr_prov_current_task, *ptr_prov_current_cred, *ptr_prov_sock_inode;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    struct cred *current_cred;
    current_cred = get_task_cred(current_task);

    ptr_prov_current_task = get_task_provenance(current_task, true);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov_current_cred = get_or_create_cred_prov(current_cred);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_sock_inode = get_or_create_inode_prov((struct inode *)bpf_inode_from_sock(sock));
    if (!ptr_prov_sock_inode) {
      return 0;
    }

    if (provenance_is_opaque(ptr_prov_current_cred)) {
      return 0;
    }

    generates(RL_LISTEN, current_task, ptr_prov_current_cred, ptr_prov_current_task, ptr_prov_sock_inode, NULL, 0);

    return 0;
}
#endif

/*!
 * @brief Record provenance when socket_accept hook is triggered.
 *
 * This hook is triggered when checking permission before accepting a new
 * connection.
 * Note that the new socket, @newsock, has been created and some information
 * copied to it,
 * but the accept operation has not actually been performed.
 * Since a new socket has been created after aceepting a new connection,
 * record provenance relation RL_ACCEPT_SOCKET by calling "derives" function.
 * Information flows from the old socket to the new socket.
 * Then record provenance relation RL_ACCEPT by calling "uses" function,
 * since the calling process accepts the connection.
 * Information flows from the new socket to the calling process, and eventually
 * to its cred.
 * @param sock The listening socket structure.
 * @param newsock The newly created server socket for connection.
 * @return 0 if permission is granted and no error occurred; Other error codes
 * inherited from derives and uses function.
 *
 */
#ifndef PROV_FILTER_SOCKET_ACCEPT_OFF
SEC("lsm/socket_accept")
int BPF_PROG(socket_accept, struct socket *sock, struct socket *newsock) {
    union prov_elt *ptr_prov_current_task, *ptr_prov_current_cred, *ptr_prov_sock_inode, *ptr_prov_newsock_inode;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    struct cred *current_cred;
    current_cred = get_task_cred(current_task);

    ptr_prov_current_task = get_task_provenance(current_task, true);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov_current_cred = get_or_create_cred_prov(current_cred);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_sock_inode = get_or_create_inode_prov((struct inode *)bpf_inode_from_sock(sock));
    if (!ptr_prov_sock_inode) {
      return 0;
    }
    ptr_prov_newsock_inode = get_or_create_inode_prov((struct inode *)bpf_inode_from_sock(newsock));
    if (!ptr_prov_newsock_inode) {
      return 0;
    }

    derives(RL_ACCEPT_SOCKET, ptr_prov_sock_inode, ptr_prov_newsock_inode, NULL, 0);
    uses(RL_ACCEPT, current_task, ptr_prov_newsock_inode, ptr_prov_current_task, ptr_prov_current_cred, NULL, 0);

    return 0;
}
#endif

/*!
 * @brief Record provenance when socket_sendmsg_always/socket_sendmsg hook is
 * triggered.
 *
 * This hook is triggered when checking permission before transmitting a message
 * to another socket.
 * Record provenance relation RL_SND_MSG by calling "generates" function.
 * Information flows from the calling process's cred to the calling process, and
 * eventually to the sending socket.
 * If sk_family is PF_UNIX (or any local communication) and sk_type is not
 * SOCK_DGRAM, we obtain the @peer receiving socket and its provenance,
 * and if the provenance is not NULL,
 * record provenance relation RL_RCV_UNIX by calling "derives" function.
 * Information flows from the sending socket to the receiving peer socket.
 * @param sock The socket structure.
 * @param msg The message to be transmitted.
 * @param size The size of message.
 * @return 0 if permission is granted and no error occurred; -ENOMEM if the
 * sending socket's provenance entry does not exist; Other error codes inherited
 * from generates and derives function.
 *
 */
#ifndef PROV_FILTER_SOCKET_SENDMSG_OFF
SEC("lsm/socket_sendmsg")
int BPF_PROG(socket_sendmsg, struct socket *sock, struct msghdr *msg, int size) {
    union prov_elt *ptr_prov_current_task, *ptr_prov_current_cred, *ptr_prov_sock_inode_a, *ptr_prov_sock_inode_b;
    struct sock *peer = NULL;

    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    struct cred *current_cred;
    current_cred = get_task_cred(current_task);

    ptr_prov_current_task = get_task_provenance(current_task, true);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov_current_cred = get_or_create_cred_prov(current_cred);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_sock_inode_a = get_or_create_inode_prov((struct inode *)bpf_inode_from_sock(sock));
    if (!ptr_prov_sock_inode_a) {
      return 0;
    }
    ptr_prov_sock_inode_b = NULL;

    generates(RL_SND_MSG, current_task, ptr_prov_current_cred, ptr_prov_current_task, ptr_prov_sock_inode_a, NULL, 0);
    if (ptr_prov_sock_inode_b) {
      derives(RL_RCV_UNIX, ptr_prov_sock_inode_a, ptr_prov_sock_inode_b, NULL, 0);
    }

    return 0;
}
#endif

/*!
 * @brief Record provenance when socket_recvmsg_always/socket_recvmsg hook is
 * triggered.
 *
 * This hook is triggered when checking permission before receiving a message
 * from a socket.
 * This function is similar to the above provenance_socket_sendmsg_always
 * function except the direction is reversed.
 * Specifically, if we know the sending socket, we have
 * record provenance relation RL_SND_UNIX by calling "derives" function.
 * Information flows from the sending socket (@peer) to the receiving socket
 * (@sock).
 * Then record provenance relation RL_RCV_MSG by calling "uses" function.
 * Information flows from the receiving socket to the calling process, and
 * eventually to its cred.
 * @param sock The receiving socket structure.
 * @param msg The message structure.
 * @param size The size of message structure.
 * @param flags The operational flags.
 * @return 0 if permission is granted, and no error occurred; -ENOMEM if the
 * receiving socket's provenance entry does not exist; Other error codes
 * inherited from uses and derives function.
 *
 */
#ifndef PROV_FILTER_SOCKET_RECVMSG_OFF
SEC("lsm/socket_recvmsg")
int BPF_PROG(socket_recvmsg, struct socket *sock, struct msghdr *msg, int size, int flags) {
    union prov_elt *ptr_prov_current_task, *ptr_prov_current_cred, *ptr_prov_sock_inode, *ptr_prov_sock_inode_peer;
    struct sock *peer;
    peer = NULL;

    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    struct cred *current_cred;
    current_cred = get_task_cred(current_task);

    ptr_prov_current_task = get_task_provenance(current_task, true);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov_current_cred = get_or_create_cred_prov(current_cred);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_sock_inode = get_or_create_inode_prov((struct inode *)bpf_inode_from_sock(sock));
    if (!ptr_prov_sock_inode) {
      return 0;
    }
    ptr_prov_sock_inode_peer = NULL;

    if (ptr_prov_sock_inode_peer) {
      derives(RL_SND_UNIX, ptr_prov_sock_inode_peer, ptr_prov_sock_inode, NULL, flags);
    }
    uses(RL_RCV_MSG, current_task, ptr_prov_sock_inode, ptr_prov_current_task, ptr_prov_current_cred, NULL, flags);

    return 0;
}
#endif

#ifndef PROV_FILTER_SOCKET_SOCKETPAIR_OFF
SEC("lsm/socket_socketpair")
int BPF_PROG(socket_socketpair, struct socket *socka, struct socket *sockb) {
    union prov_elt *ptr_prov_current_task, *ptr_prov_current_cred, *ptr_prov_sock_a, *ptr_prov_sock_b;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    struct cred *current_cred;
    current_cred = get_task_cred(current_task);

    ptr_prov_current_task = get_task_provenance(current_task, true);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov_current_cred = get_or_create_cred_prov(current_cred);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_sock_a = get_or_create_inode_prov((struct inode *)bpf_inode_from_sock(socka));
    if (!ptr_prov_sock_a) {
      return 0;
    }
    ptr_prov_sock_b = get_or_create_inode_prov((struct inode *)bpf_inode_from_sock(sockb));
    if (!ptr_prov_sock_b) {
      return 0;
    }

    generates(RL_SOCKET_PAIR_CREATE, current_task, ptr_prov_current_cred, ptr_prov_current_task, ptr_prov_sock_a, NULL, 0);
    generates(RL_SOCKET_PAIR_CREATE, current_task, ptr_prov_current_cred, ptr_prov_current_task, ptr_prov_sock_b, NULL, 0);

    return 0;
}
#endif

/*!
 * @brief Record provenance when unix_stream_connect hook is triggered.
 *
 * This hook is triggered when checking permissions before establishing a Unix
 * domain stream connection b]etween @sock and @other.
 * Unix domain connection is local communication.
 * Since this is simply to connect (no information should flow between the two
 * local sockets yet), we do not use receiving socket information @other or new
 * socket @newsk.
 * Record provenance relation RL_CONNECT by calling "generates" function.
 * Information flows from the calling process's cred to the task , and
 * eventually to the sending socket.
 * @param sock The (sending) sock structure.
 * @param other The peer (i.e., receiving) sock structure. Unused parameter.
 * @param newsk The new sock structure. Unused parameter.
 * @return 0 if permission is granted; Other error code inherited from generates
 * function.
 *
 */
#ifndef PROV_FILTER_UNIX_STREAM_CONNECT_OFF
SEC("lsm/unix_stream_connect")
int BPF_PROG(unix_stream_connect, struct sock *sock, struct sock *other, struct sock *newsk) {
    union prov_elt *ptr_prov_current_task, *ptr_prov_current_cred, *ptr_prov_sock_inode;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    struct cred *current_cred;
    current_cred = get_task_cred(current_task);

    ptr_prov_current_task = get_task_provenance(current_task, true);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov_current_cred = get_or_create_cred_prov(current_cred);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_sock_inode = get_or_create_inode_prov((struct inode *)bpf_inode_from_sock(sock->sk_socket));
    if (!ptr_prov_sock_inode) {
      return 0;
    }

    generates(RL_CONNECT_UNIX_STREAM, current_task, ptr_prov_current_cred, ptr_prov_current_task, ptr_prov_sock_inode, NULL, 0);

    return 0;
}
#endif

/*!
 * @brief Record provenance when unix_may_send hook is triggered.
 *
 * This hook is triggered when checking permissions before connecting or sending
 * datagrams from @sock to @other.
 * Record provenance relation RL_SND_UNIX by calling "derives" function.
 * Information flows from the sending socket (@sock) to the receiving socket
 * (@other).
 * @param sock The socket structure.
 * @param other The peer socket structure.
 * @return 0 if permission is granted and no error occurred; Other error codes
 * inherited from derives function.
 *
 */
#ifndef PROV_FILTER_UNIX_MAY_SEND_OFF
SEC("lsm/unix_may_send")
int BPF_PROG(unix_may_send, struct socket *sock, struct socket *other) {
    union prov_elt *ptr_prov_inode_sock, *ptr_prov_inode_other;

    ptr_prov_inode_sock = get_or_create_inode_prov((struct inode *)bpf_inode_from_sock(sock));
    if (!ptr_prov_inode_sock) {
      return 0;
    }
    ptr_prov_inode_other = get_or_create_inode_prov((struct inode *)bpf_inode_from_sock(other));
    if (!ptr_prov_inode_other) {
      return 0;
    }

    derives(RL_SND_UNIX, ptr_prov_inode_sock, ptr_prov_inode_other, NULL, 0);

    return 0;
}
#endif

/*!
 * @brief Record provenance when bprm_creds_for_exec hook is triggered.
 *
 * This hook is triggered when saving security information in the bprm->security
 * field, typically based on information about the bprm->file, for later use by
 * the apply_creds hook.
 * This hook may also optionally check permissions (e.g. for transitions between
 * security domains).
 * The hook can tell whether it has already been called by checking to see if
 * @bprm->security is non-NULL.
 * If so, then the hook may decide either to retain the security information
 * saved earlier or to replace it.
 * Since cred is based on information about the @bprm->file,
 * information flows from the inode of bprm->file to bprm->cred.
 * Therefore, record provenance relation RL_EXEC by calling "derives" function.
 * Relation is not recorded if the inode of bprm->file is set to be opaque.
 * @param bprm The linux_binprm structure.
 * @return 0 if the hook is successful and permission is granted; -ENOMEM if
 * bprm->cred's provenance does not exist. Other error codes inherited from
 * derives function.
 *
 */
#ifndef PROV_FILTER_BPRM_CREDS_FOR_EXEC_OFF
SEC("lsm/bprm_creds_for_exec")
int BPF_PROG(bprm_creds_for_exec, struct linux_binprm *bprm) {
    union prov_elt *ptr_prov_cred, *ptr_prov_inode;

    ptr_prov_cred = get_or_create_cred_prov(bprm->cred);
    if (!ptr_prov_cred) {
      return 0;
    }
    ptr_prov_inode = get_or_create_inode_prov(bprm->file->f_inode);
    if (!ptr_prov_inode) {
      return 0;
    }

    derives(RL_EXEC, ptr_prov_inode, ptr_prov_cred, NULL, 0);

    return 0;
}
#endif

/*!
 * @brief Record provenance when bprm_committing_creds hook is triggered.
 *
 * This hook is triggered when preparing to install the new security attributes
 * of a process being transformed by an execve operation,
 * based on the old credentials pointed to by @current->cred,
 * and the information set in @bprm->cred by the bprm_creds_for_exec hook.
 * @bprm points to the linux_binprm
 *	structure.  This hook is a good place to perform state changes on the
 *	process such as closing open file descriptors to which access will no
 *	longer be granted when the attributes are changed.  This is called
 *	immediately before commit_creds().
 * Since the process is being transformed to the new process,
 * record provenance relation RL_EXEC_TASK by calling "derives" function.
 * Information flows from the old process's cred to the new process's cred.
 * Cred can also be set by bprm_set_creds, so
 * record provenance relation RL_EXEC by calling "derives" function.
 * Information flows from the bprm->file's cred to the new process's cred.
 * The old process gets the name of the new process by calling record_node_name
 * function.
 * Note that if bprm->file's provenance is set to be opaque,
 * the new process bprm->cred's provenance will therefore be opaque and we do
 * not track any of the relations.
 * @param bprm points to the linux_binprm structure.
 *
 */
#ifndef PROV_FILTER_BPRM_COMMITTING_CREDS_OFF
SEC("lsm/bprm_committing_creds")
int BPF_PROG(bprm_committing_creds, struct linux_binprm *bprm) {
    union prov_elt *ptr_prov_current_task, *ptr_prov_current_cred, *ptr_prov_cred;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    struct cred *current_cred;
    current_cred = get_task_cred(current_task);

    ptr_prov_current_task = get_task_provenance(current_task, true);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov_current_cred = get_or_create_cred_prov(current_cred);
    if (!ptr_prov_current_cred) {
      return 0;
    }
    ptr_prov_cred = get_or_create_cred_prov(bprm->cred);
    if (!ptr_prov_cred) {
      return 0;
    }

    generates(RL_EXEC_TASK, current_task, ptr_prov_current_cred, ptr_prov_current_task, ptr_prov_cred, NULL, 0);

    return 0;
}
#endif

#ifndef PROV_FILTER_KERNEL_READ_FILE_OFF
SEC("lsm/kernel_read_file")
int BPF_PROG(kernel_read_file, struct file *file, enum kernel_read_file_id id) {
    union prov_elt *ptr_prov_current_task, *ptr_prov_inode;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();

    ptr_prov_current_task = get_task_provenance(current_task, true);
    if (!ptr_prov_current_task) {
      return 0;
    }
    ptr_prov_inode = get_or_create_inode_prov(file->f_inode);
    if (!ptr_prov_inode) {
      return 0;
    }

    switch (id) {
      case READING_UNKNOWN:
        record_influences_kernel(RL_LOAD_UNKNOWN, ptr_prov_inode, ptr_prov_current_task, file);
        break;
      case READING_FIRMWARE:
        record_influences_kernel(RL_LOAD_FIRMWARE, ptr_prov_inode, ptr_prov_current_task, file);
        break;
      case READING_MODULE:
        record_influences_kernel(RL_LOAD_MODULE, ptr_prov_inode, ptr_prov_current_task, file);
        break;
      case READING_KEXEC_IMAGE:
        record_influences_kernel(RL_LOAD_KEXEC_IMAGE, ptr_prov_inode, ptr_prov_current_task, file);
        break;
      case READING_KEXEC_INITRAMFS:
        record_influences_kernel(RL_LOAD_KEXEC_INITRAMFS, ptr_prov_inode, ptr_prov_current_task, file);
        break;
      case READING_POLICY:
        record_influences_kernel(RL_LOAD_POLICY, ptr_prov_inode, ptr_prov_current_task, file);
        break;
      case READING_X509_CERTIFICATE:
        record_influences_kernel(RL_LOAD_CERTIFICATE, ptr_prov_inode, ptr_prov_current_task, file);
        break;
      default: // should not happen
        record_influences_kernel(RL_LOAD_UNDEFINED, ptr_prov_inode, ptr_prov_current_task, file);
        break;
    }

    return 0;
}
#endif
