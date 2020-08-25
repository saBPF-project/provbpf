/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <linux/limits.h>

#include "sockaddr.h"
#include "linux/provenance.h"
#include "linux/provenance_types.h"

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

static __always_inline void update_task_prov(struct task_struct *task,
                                                union prov_elt *prov){
    struct mm_struct *mm = task->mm;

    prov->task_info.identifier.node_id.type=ACT_TASK;
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
    __builtin_memset(&prov, 0, sizeof(union prov_elt));
    /* populate the provenance record for the new task */
    update_task_prov(task, &prov);

    /* TODO: CODE HERE
     * Update the task map here to save the task provenance state.
     *
     * bpf_map_update_elem(&task_map, &pid, &prov, BPF_NOEXIST);
     */
    bpf_map_update_elem(&task_map, &key, &prov, BPF_NOEXIST);

    /* Record the provenance to the ring buffer */
    record_provenance(&prov);
    return 0;
}

SEC("lsm/task_free")
int BPF_PROG(task_free, struct task_struct *task) {
    uint64_t key = get_key(task);
    union prov_elt *prov;

    // we retrieve the provenance that was created in alloc
    prov = bpf_map_lookup_elem(&task_map, &key);
    if (!prov)
        goto out;

    /* populate the provenance record for the new task */
    update_task_prov(task, prov);

    /* Record the provenance to the ring buffer */
    record_provenance(prov);
    // TODO record more

out:
    /* we delete the provenance associated to the task */
    bpf_map_delete_elem(&task_map, &key);
    return 0;
}
