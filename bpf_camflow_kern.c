/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <linux/limits.h>

#include "sockaddr.h"
#include "linux/provenance.h"

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

//TODO: is there a better way to assign a key to a kernel object?
static __always_inline uint64_t get_key(void* object) {
    return (uint64_t)object;
}

SEC("lsm/task_alloc")
int BPF_PROG(task_alloc, struct task_struct *task, unsigned long clone_flags) {
    uint32_t pid = task->pid;
    uint64_t unique = get_key(task);
    /* populate the provenance record for the new task */
    //TODO: more information needs to be added to the structure
    union prov_elt prov = {
        .task_info.pid = pid,
        .task_info.utime = unique
    };
    /* TODO: CODE HERE
     * Update the task map here to save the task provenance state.
     *
     * bpf_map_update_elem(&task_map, &pid, &prov, BPF_NOEXIST);
     */

    /* Record the provenance to the ring buffer */
    record_provenance(&prov);
    return 0;
}

SEC("lsm/task_free")
int BPF_PROG(task_free, struct task_struct *task) {
    uint32_t pid = task->pid;
    uint64_t unique = get_key(task);
    union prov_elt prov = {
        .task_info.pid = pid,
        .task_info.utime = unique
    };
    /* TODO: CODE HERE
     * Update the task map here to remove the task provenance state.
     *
     * bpf_map_delete_elem(&task_map, &pid);
     */

    /* Record the provenance to the ring buffer */
    record_provenance(&prov);
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
  // Count inode provenance
  // count(&my_map);
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
