/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <linux/limits.h>

#include "sockaddr.h"
#include "linux/provenance.h"
#include "linux/provenance_types.h"
#include "camflow_bpf_id.h"

char _license[] SEC("license") = "GPL";

#define KB 1024
#define KB_MASK         (~(KB - 1))

// NOTE: ring buffer reference:
// https://elixir.bootlin.com/linux/v5.8/source/tools/testing/selftests/bpf/progs/test_ringbuf.c
struct bpf_map_def SEC("maps") r_buf = {
    .type = BPF_MAP_TYPE_RINGBUF,
    /* NOTE: The minimum size seems to be 1 << 12.
     * Any value smaller than this results in
     * runtime error. */
    .max_entries = 1 << 12,
};

struct bpf_map_def SEC("maps") task_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint64_t),
    .value_size = sizeof(union prov_elt),
    .max_entries = 4096, // NOTE: set as big as possible; real size is dynamically adjusted
};

struct bpf_map_def SEC("maps") ids_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(struct id_elem),
    .max_entries = ID_MAX_ENTRY,
};

static __always_inline uint64_t prov_next_id(uint32_t key)	{
    struct id_elem *val = bpf_map_lookup_elem(&ids_map, &key);
    if(!val)
        return 0;
    __sync_fetch_and_add(&val->id, 1);
    // this is wrong but cannot return value directly from __sync_fetch_and_add
    // someone needs to inv
    // Perhaps a lock is needed to avoid race conditions?
    return val->id;
}

static __always_inline uint64_t prov_get_id(uint32_t key) {
    struct id_elem *val = bpf_map_lookup_elem(&ids_map, &key);
    if(!val)
        return 0;
    return val->id;
}

static __always_inline void record_provenance(union prov_elt* prov){
    bpf_ringbuf_output(&r_buf, prov, sizeof(union prov_elt), 0);
}

//TODO: is there a better way to assign a key to a kernel object?
static __always_inline uint64_t get_key(void* object) {
    return (uint64_t)object;
}

static __always_inline uint64_t u64_max(uint64_t a, uint64_t b) {
    return (a > b) ? a : b;
}

static __always_inline void prov_init(union prov_elt *prov, uint64_t type) {
    prov->node_info.identifier.node_id.type=type;
    prov->node_info.identifier.node_id.id = prov_next_id(NODE_ID_INDEX);
    prov->node_info.identifier.node_id.boot_id = prov_get_id(BOOT_ID_INDEX);
    prov->node_info.identifier.node_id.machine_id = prov_get_id(MACHINE_ID_INDEX);
}

//TODO: Need to further refactor this function.
static __always_inline void prov_update_task(struct task_struct *task,
                                             union prov_elt *prov) {

    bpf_probe_read(&prov->task_info.pid, sizeof(prov->task_info.pid), &task->pid);
    bpf_probe_read(&prov->task_info.vpid, sizeof(prov->task_info.vpid), &task->tgid);
    bpf_probe_read(&prov->task_info.utime, sizeof(prov->task_info.utime), &task->utime);
    bpf_probe_read(&prov->task_info.stime, sizeof(prov->task_info.stime), &task->stime);
    struct mm_struct *mm;
    bpf_probe_read(&mm, sizeof(mm), &task->mm);
    bpf_probe_read(&prov->task_info.vm, sizeof(prov->task_info.vm), &mm->total_vm);
    prov->task_info.vm = prov->task_info.vm * IOC_PAGE_SIZE / KB;
    struct mm_rss_stat rss_stat;
    bpf_probe_read(&rss_stat, sizeof(rss_stat), &mm->rss_stat);
    prov->task_info.rss = (rss_stat.count[MM_FILEPAGES].counter +
                                       rss_stat.count[MM_ANONPAGES].counter +
                                       rss_stat.count[MM_SHMEMPAGES].counter) * IOC_PAGE_SIZE / KB;
    uint64_t current_task_hw_vm, current_task_hw_rss;
    bpf_probe_read(&current_task_hw_vm, sizeof(current_task_hw_vm), &mm->hiwater_vm);
    prov->task_info.hw_vm = u64_max(current_task_hw_vm, prov->task_info.vm) * IOC_PAGE_SIZE / KB;
    bpf_probe_read(&current_task_hw_rss, sizeof(current_task_hw_rss), &mm->hiwater_rss);
    prov->task_info.hw_rss = u64_max(current_task_hw_rss, prov->task_info.rss) * IOC_PAGE_SIZE / KB;
#ifdef CONFIG_TASK_IO_ACCOUNTING
    bpf_probe_read(&prov->task_info.rbytes, sizeof(prov->task_info.rbytes), &task->ioac.read_bytes);
    prov->task_info.rbytes &= KB_MASK;
    bpf_probe_read(&prov->task_info.wbytes, sizeof(prov->task_info.wbytes), &task->ioac.write_bytes);
    prov->task_info.wbytes &= KB_MASK;
    bpf_probe_read(&prov->task_info.cancel_wbytes, sizeof(prov->task_info.cancel_wbytes), &task->ioac.cancelled_write_bytes);
    prov->task_info.cancel_wbytes &= KB_MASK;
#else
    bpf_probe_read(&prov->task_info.rbytes, sizeof(prov->task_info.rbytes), &task->ioac.rchar);
    prov->task_info.rbytes &= KB_MASK;
    bpf_probe_read(&prov->task_info.wbytes, sizeof(prov->task_info.wbytes), &task->ioac.wchar);
    prov->task_info.wbytes &= KB_MASK;
    prov->task_info.cancel_wbytes = 0;
#endif
}

static __always_inline union prov_elt* get_or_create_task_prov(
                                                struct task_struct *task,
                                                union prov_elt *new_prov) {
    uint64_t key = get_key(task);
    union prov_elt *old_prov = bpf_map_lookup_elem(&task_map, &key);
    // provenance already tracked
    if (old_prov) {
        prov_update_task(task, old_prov);
        return old_prov;
    } else { // new task
        __builtin_memset(new_prov, 0, sizeof(union prov_elt));
        prov_init(new_prov, ACT_TASK);
        prov_update_task(task, new_prov);
        bpf_map_update_elem(&task_map, &key, new_prov, BPF_NOEXIST);
        return new_prov;
    }
}

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
