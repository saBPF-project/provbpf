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

char _license[] SEC("license") = "GPL";

SEC("lsm/task_alloc")
int BPF_PROG(task_alloc, struct task_struct *task, unsigned long clone_flags) {
    union prov_elt prov, prov_current;
    union prov_elt *ptr_prov, *ptr_prov_current;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();

    ptr_prov_current = get_or_create_task_prov(current_task, &prov_current);
    ptr_prov = get_or_create_task_prov(task, &prov);

    /* Record the tasks provenance to the ring buffer */
    record_provenance(ptr_prov_current);
    record_provenance(ptr_prov);

    /* TODO: CODE HERE
     * Record provenance relations as the result of task allocation.
     */
    return 0;
}

SEC("lsm/task_free")
int BPF_PROG(task_free, struct task_struct *task) {
    uint64_t key = get_key(task);
    union prov_elt prov;
    union prov_elt *ptr_prov;

    ptr_prov = get_or_create_task_prov(task, &prov);

    /* Record the provenance to the ring buffer */
    record_provenance(ptr_prov);
    /* TODO: CODE HERE
     * Record the task_free relation.
     */

    /* Delete task provenance since the task no longer exists */
    bpf_map_delete_elem(&task_map, &key);

    return 0;
}
