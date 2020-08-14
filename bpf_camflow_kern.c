/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <linux/limits.h>

#include "sockaddr.h"
#include "provenance.h"

char _license[] SEC("license") = "GPL";

// NOTE: example reference:
// https://elixir.bootlin.com/linux/v5.8/source/tools/testing/selftests/bpf/progs/test_ringbuf.c
struct bpf_map_def SEC("maps") r_buf = {
    .type = BPF_MAP_TYPE_RINGBUF,
    .max_entries = 1 << 2,
};

struct bpf_map_def SEC("maps") task_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(struct task_prov_struct),
    .max_entries = 4096, // NOTE: set as big as possible; real size is dynamically adjusted
};

SEC("lsm/task_alloc")
int BPF_PROG(task_alloc, struct task_struct *task, unsigned long clone_flags) {
    uint32_t pid  = task->pid;
    struct task_prov_struct prov = {.pid = task->pid};
    bpf_map_update_elem(&task_map, &pid, &prov, BPF_NOEXIST);
    // Add an entry to the ring buffer (not tested)
    bpf_ringbuf_output(&r_buf, &prov, sizeof(struct task_prov_struct), 0);
    return 0;
}

SEC("lsm/task_free")
int BPF_PROG(task_free, struct task_struct *task) {
    uint32_t pid  = 0;
    bpf_map_delete_elem(&task_map, &pid);
    return 0;
}
