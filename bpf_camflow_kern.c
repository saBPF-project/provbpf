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
    struct mm_struct *mm = task->mm;

    prov->task_info.pid = task->pid;
    prov->task_info.vpid = task->tgid;
    prov->task_info.utime = task->utime;
    prov->task_info.stime = task->stime;
    prov->task_info.vm = mm->total_vm * IOC_PAGE_SIZE / KB;
    prov->task_info.rss = (mm->rss_stat.count[MM_FILEPAGES].counter +
                         mm->rss_stat.count[MM_ANONPAGES].counter +
                         mm->rss_stat.count[MM_SHMEMPAGES].counter) * IOC_PAGE_SIZE / KB;
    prov->task_info.hw_vm = u64_max(mm->hiwater_vm, mm->total_vm) * IOC_PAGE_SIZE / KB;
    prov->task_info.hw_rss = u64_max(mm->hiwater_rss, prov->task_info.rss) * IOC_PAGE_SIZE / KB;
#ifdef CONFIG_TASK_IO_ACCOUNTING
    prov->task_info.rbytes = task->ioac.read_bytes & KB_MASK;
    prov->task_info.wbytes = task->ioac.write_bytes & KB_MASK;
    prov->task_info.cancel_wbytes = task->ioac.cancelled_write_bytes & KB_MASK;
#else
    prov->task_info.rbytes = task->ioac.rchar & KB_MASK;
    prov->task_info.wbytes = task->ioac.wchar & KB_MASK;
    prov->task_info.cancel_wbytes = 0;
#endif
}

SEC("lsm/task_alloc")
int BPF_PROG(task_alloc, struct task_struct *task, unsigned long clone_flags) {
    uint64_t key = get_key(task);
    union prov_elt prov;
    __builtin_memset(&prov, 0, sizeof(union prov_elt)); // this is needed

    prov_init(&prov, ACT_TASK);

    /* Populate a provenance record for the new task */
    //TODO: is it necessary to populate everything in prov_update_task?
    //      It is perhaps a good idea to refactor prov_update_task.
    prov_update_task(task, &prov);

    /* Update the task map here to save the task provenance state */
    bpf_map_update_elem(&task_map, &key, &prov, BPF_NOEXIST);

    /* Record the provenance to the ring buffer */
    record_provenance(&prov);
    /* TODO: CODE HERE
     * Record provenance relations as the result of task allocation.
     */
    return 0;
}

SEC("lsm/task_free")
int BPF_PROG(task_free, struct task_struct *task) {
    uint64_t key = get_key(task);
    union prov_elt *prov;
    /* Retrieve the provenance created in task_alloc. */
    prov = bpf_map_lookup_elem(&task_map, &key);
    if (!prov) {
#ifdef CONFIG_DEBUG
        /* bpf_trace_printk() is used for debugging.
	 * Check for output through:
	 * cat /sys/kernel/debug/tracing/trace_pipe */
        /* We may not have the provenance of a task since
	 * we are not tracking provenance from the very
	 * beginning of time.
	 * TODO: we simply log this issue for now, but
	 * we may want to come up with a better idea. */
        char err[] = "task_free cannot be logged because the task does not exist\n";
	bpf_trace_printk(err, sizeof(err));
#endif
        return 0;
    }

    /* Update task provenance */
    //TODO: is it necessary to repopulate everything here?
    // No it is not, but we need to figure out what needs to be
    prov_update_task(task, prov);

    /* Record the provenance to the ring buffer */
    record_provenance(prov);
    /* TODO: CODE HERE
     * Record the task_free relation.
     */

    /* Delete task provenance since the task no longer exists */
    bpf_map_delete_elem(&task_map, &key);

    return 0;
}
