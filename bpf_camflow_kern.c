/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <linux/limits.h>

#include "sockaddr.h"
#include "provenance.h"

char _license[] SEC("license") = "GPL";

struct bpf_map_def SEC("maps") my_map = {
        .type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(u32),
        .value_size = sizeof(u32),
        .max_entries = 1,
};

struct bpf_map_def SEC("maps") task_map = {
        .type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(u32), // probably wants to change
        .value_size = sizeof(struct task_prov_struct),
        .max_entries = 4096, // how to setup the size? is there as big as needed option?
};

static __always_inline void count(void *map)
{
	u32 key = 0;
	u32 *value, init_val = 1;

  // retrieve value of element 0
	value = bpf_map_lookup_elem(map, &key);
  // increment if exists, otherwise insert
	if (value)
		*value += 1;
	else
		bpf_map_update_elem(map, &key, &init_val, BPF_NOEXIST);
}

SEC("lsm/task_alloc")
int BPF_PROG(task_alloc, struct task_struct *task, unsigned long clone_flags)
{
  uint32_t pid  = task->pid;
  /* it needs to be initialised */
  struct task_prov_struct prov = {.pid = task->pid};
  bpf_map_update_elem(&task_map, &pid, &prov, BPF_NOEXIST);
  count(&my_map);
	return 0;
}

SEC("lsm/task_free")
int BPF_PROG(task_free, struct task_struct *task)
{
  uint32_t pid  = 0;
  bpf_map_delete_elem(&task_map, &pid);
  return 0;
}
