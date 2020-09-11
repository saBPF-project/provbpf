/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#ifndef __KERN_BPF_MAPS_H
#define __KERN_BPF_MAPS_H

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
    .max_entries = 4096, // TODO: set as big as possible; real size is dynamically adjusted
};

struct bpf_map_def SEC("maps") inode_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct inode_key),
    .value_size = sizeof(union prov_elt),
    .max_entries = 4096, // TODO: set as big as possible; real size is dynamically adjusted
};

struct bpf_map_def SEC("maps") ids_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(struct id_elem),
    .max_entries = ID_MAX_ENTRY,
};

#endif
