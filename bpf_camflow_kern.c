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
        .key_size = sizeof(uint32_t),
        .value_size = sizeof(uint32_t),
        .max_entries = 1,
};

struct bpf_map_def SEC("maps") task_map = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(uint32_t), // probably wants to change
        .value_size = sizeof(struct task_prov_struct),
        .max_entries = 4096, // how to setup the size? is there as big as needed option?
};

struct bpf_map_def SEC("maps") inode_map = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(uint32_t) + sizeof(uuid_t), // 20 bytes, 4 bytes for the inode ino, 16 bytes for the superblock UUID
        .value_size = sizeof(struct inode_prov_struct),
        .max_entries = 4096, // how to setup the size? is there as big as needed option?
};

static __always_inline void count(void *map)
{
	uint32_t key = 0;
	uint32_t *value, init_val = 1;

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

SEC("lsm/inode_alloc_security")
int BPF_PROG(inode_alloc_security, struct inode *inode) {
  uint32_t i_id[5];
  i_id[0] = inode->i_ino;
  struct inode_prov_struct prov = {
    .ino = inode->i_ino,
    .mode = inode->i_mode
  };
  int i;
  #pragma unroll
  for (i = 0; i < 4; i++) {
      prov.sb_uuid[4 * i] = ((inode->i_sb)->s_uuid).b[4 * i];
      prov.sb_uuid[4 * i + 1] = ((inode->i_sb)->s_uuid).b[4 * i + 1];
      prov.sb_uuid[4 * i + 2] = ((inode->i_sb)->s_uuid).b[4 * i + 2];
      prov.sb_uuid[4 * i + 3] = ((inode->i_sb)->s_uuid).b[4 * i + 3];

      i_id[i + 1] = (prov.sb_uuid[4 * i] << 24) + (prov.sb_uuid[4 * i + 1] << 16) + (prov.sb_uuid[4 * i + 2] << 8) + prov.sb_uuid[4 * i + 3];
  }

  bpf_map_update_elem(&inode_map, &i_id, &prov, BPF_NOEXIST);
  count(&my_map);
	return 0;
}

SEC("lsm/inode_free_security")
int BPF_PROG(inode_free_security, struct inode *inode) {
  uint32_t i_id[5];
  i_id[0] = inode->i_ino;
  int i;
  #pragma unroll
  for (i = 0; i < 4; i++) {
      i_id[i + 1] = (((inode->i_sb)->s_uuid).b[4 * i] << 24) + (((inode->i_sb)->s_uuid).b[4 * i + 1] << 16) + (((inode->i_sb)->s_uuid).b[4 * i + 2] << 8) + ((inode->i_sb)->s_uuid).b[4 * i + 3];
  }
  bpf_map_delete_elem(&inode_map, &i_id);
  return 0;
}
