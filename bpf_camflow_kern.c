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
#include "kern_bpf_relation.h"

char _license[] SEC("license") = "GPL";

/* LSM hooks names can be reference here:
 * https://elixir.bootlin.com/linux/v5.8/source/include/linux/lsm_hook_defs.h
 * Template is: SEC("lsm/HOOK_NAMES")
 */

SEC("lsm/task_alloc")
int BPF_PROG(task_alloc, struct task_struct *task, unsigned long clone_flags) {
    union prov_elt *ptr_prov, *ptr_prov_current;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();

    ptr_prov_current = get_or_create_task_prov(current_task);
    if(!ptr_prov_current) // something is wrong
        return 0;
    ptr_prov = get_or_create_task_prov(task);
    if(!ptr_prov) // something is wrong
        return 0;

    /* Record the tasks provenance to the ring buffer */
    record_provenance(ptr_prov_current);
    record_provenance(ptr_prov);

    record_relation(RL_CLONE, ptr_prov_current, ptr_prov, NULL, clone_flags);
    return 0;
}

SEC("lsm/task_free")
int BPF_PROG(task_free, struct task_struct *task) {
    uint64_t key;
    get_key(task);
    union prov_elt *ptr_prov;

    ptr_prov = get_or_create_task_prov(task);
    if(!ptr_prov) // something is wrong
        return 0;

    /* Record task terminate */
    record_terminate(RL_TERMINATE_TASK, ptr_prov);

    /* Delete task provenance since the task no longer exists */
    bpf_map_delete_elem(&task_map, &key);

    return 0;
}

SEC("lsm/inode_alloc_security")
int BPF_PROG(inode_alloc_security, struct inode *inode) {
    union prov_elt *ptr_prov;

    ptr_prov = get_or_create_inode_prov(inode);
    if(!ptr_prov) // something is wrong
        return 0;

    record_provenance(ptr_prov);

    /* TODO: CODE HERE
     * Record the inode_alloc relation.
     */

    return 0;
}

SEC("lsm/inode_free_security")
int BPF_PROG(inode_free_security, struct inode *inode) {
    uint64_t key = get_key(inode);
    union prov_elt *ptr_prov;

    ptr_prov = get_or_create_inode_prov(inode);
    if(!ptr_prov) // something is wrong
        return 0;

    /* Record inode freed */
    record_terminate(RL_FREED, ptr_prov);

    bpf_map_delete_elem(&inode_map, &key);
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

    ptr_prov = get_or_create_cred_prov(cred, current_task);
    if (!ptr_prov) {
      return 0;
    }

    record_provenance(ptr_prov);

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
    ptr_prov = get_or_create_cred_prov(cred, current_task);
    if (!ptr_prov) {
      return 0;
    }

    // Record cred freed
    record_terminate(RL_TERMINATE_PROC, ptr_prov);

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

    ptr_prov_new = get_or_create_cred_prov(new, current_task);
    if (!ptr_prov_new) {
      return 0;
    }
    ptr_prov_old = get_or_create_cred_prov(old, current_task);
    if (!ptr_prov_old) {
      return 0;
    }
    ptr_prov_task = get_or_create_task_prov(current_task);
    if (!ptr_prov_task) {
      return 0;
    }

    record_provenance(ptr_prov_new);
    record_provenance(ptr_prov_old);
    record_provenance(ptr_prov_task);

    // Record cred prepare relation
    record_relation(RL_PROC_READ, ptr_prov_old, ptr_prov_task, NULL, 0);
    record_relation(RL_CLONE_MEM, ptr_prov_task, ptr_prov_new, NULL, 0);

    return 0;
}
