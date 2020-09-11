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
#include "kern_bpf_relation.h"

char _license[] SEC("license") = "GPL";

/* LSM hooks names can be reference here:
 * https://elixir.bootlin.com/linux/v5.8/source/include/linux/lsm_hook_defs.h
 * Template is: SEC("lsm/HOOK_NAMES")
 */

SEC("lsm/task_alloc")
int BPF_PROG(task_alloc, struct task_struct *task, unsigned long clone_flags) {
    union prov_elt prov_tmp;
    union prov_elt *ptr_prov, *ptr_prov_current;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();

    ptr_prov_current = get_or_create_task_prov(current_task, &prov_tmp);
    if(!ptr_prov_current) // something is wrong
        return 0;
    ptr_prov = get_or_create_task_prov(task, &prov_tmp);
    if(!ptr_prov) // something is wrong
        return 0;

    /* Record the tasks provenance to the ring buffer */
    record_provenance(ptr_prov_current);
    record_provenance(ptr_prov);

    // return stack error at compilation, need to figure how to fix this
    record_relation(RL_CLONE, ptr_prov_current, ptr_prov, NULL, clone_flags, &prov_tmp);
    return 0;
}

SEC("lsm/task_free")
int BPF_PROG(task_free, struct task_struct *task) {
    uint64_t key;
    get_key(task);
    union prov_elt prov_tmp;
    union prov_elt *ptr_prov;

    ptr_prov = get_or_create_task_prov(task, &prov_tmp);
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
    union prov_elt prov_tmp;
    union prov_elt *ptr_prov;

    ptr_prov = get_or_create_inode_prov(inode, &prov_tmp);
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
    union prov_elt prov_tmp;
    union prov_elt *ptr_prov;

    ptr_prov = get_or_create_inode_prov(inode, &prov_tmp);
    if(!ptr_prov) // something is wrong
        return 0;

    /* Record inode freed */
    record_terminate(RL_FREED, ptr_prov);

    bpf_map_delete_elem(&inode_map, &key);
    return 0;
}
