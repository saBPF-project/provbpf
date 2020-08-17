/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <linux/limits.h>

#include "sockaddr.h"
#include "provenance.h"

char _license[] SEC("license") = "GPL";

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
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(union prov_elt),
    .max_entries = 4096, // NOTE: set as big as possible; real size is dynamically adjusted
};

static __always_inline void record_provenance(union prov_elt* prov){
  bpf_ringbuf_output(&r_buf, prov, sizeof(union prov_elt), 0);
}

SEC("lsm/task_alloc")
int BPF_PROG(task_alloc, struct task_struct *task, unsigned long clone_flags) {
    uint32_t pid = task->pid;
    uint64_t unique = (uint64_t)task;
    union prov_elt prov = {.task_info.pid = pid,.task_info.utime = unique};
    //bpf_map_update_elem(&task_map, &pid, &prov, BPF_NOEXIST);
    record_provenance(&prov);
    return 0;
}

SEC("lsm/task_free")
int BPF_PROG(task_free, struct task_struct *task) {
    uint32_t pid = task->pid;
    uint64_t unique = (uint64_t)task;
    union prov_elt prov = {.task_info.pid = pid,.task_info.utime = unique};
    record_provenance(&prov);
    //bpf_map_delete_elem(&task_map, &pid);
    return 0;
}
