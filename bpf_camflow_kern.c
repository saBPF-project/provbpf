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
    .value_size = sizeof(struct task_prov_struct),
    .max_entries = 4096, // NOTE: set as big as possible; real size is dynamically adjusted
};

struct entry {
    uint32_t pid;
};

SEC("lsm/task_alloc")
int BPF_PROG(task_alloc, struct task_struct *task, unsigned long clone_flags) {
    struct entry *prov_entry;
    uint32_t pid  = task->pid;
    struct task_prov_struct prov = {.pid = task->pid};
    bpf_map_update_elem(&task_map, &pid, &prov, BPF_NOEXIST);
    /* Add an entry to the ring buffer by first
     * reserving some space in the ring buffer. */
    prov_entry = bpf_ringbuf_reserve(&r_buf, sizeof(*prov_entry), 0);
    /* Reserving space failed. */
    if (!prov_entry) {
	/* bpf_trace_printk() is used for debugging. 
	 * Check for output through:
	 * cat /sys/kernel/debug/tracing/trace_pipe */
	char err[] = "Reserving space in the ring buffer for pid failed: %u\n";
	bpf_trace_printk(err, sizeof(err), pid);
        return 1;
    }
    /* Populate the entry with data. */
    prov_entry->pid = pid;
    char fmt[] = "Submitting pid to the ring buffer: %u\n";
    bpf_trace_printk(fmt, sizeof(fmt), prov_entry->pid);
    /* prov_entry is ready to be committed. */
    bpf_ringbuf_submit(prov_entry, 0);
    return 0;
}

SEC("lsm/task_free")
int BPF_PROG(task_free, struct task_struct *task) {
    uint32_t pid  = 0;
    bpf_map_delete_elem(&task_map, &pid);
    return 0;
}
