/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020-2021 Harvard University
 * Copyright (C) 2020-2021 University of Bristol
 *
 * Author: Thomas Pasquier <thomas.pasquier@bristol.ac.uk>
 * Author: Bogdan Stelea <bs17580@bristol.ac.uk>
 * Author: Soo Yee Lim <sooyee.lim@bristol.ac.uk>
 * Author: Xueyuan "Michael" Han <hanx@g.harvard.edu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 */
#ifndef __KERN_BPF_MAPS_H
#define __KERN_BPF_MAPS_H

// NOTE: ring buffer reference:
// https://elixir.bootlin.com/linux/v5.8/source/tools/testing/selftests/bpf/progs/test_ringbuf.c
struct bpf_map_def SEC("maps") r_buf = {
    .type = BPF_MAP_TYPE_RINGBUF,
    /* NOTE: The minimum size seems to be 1 << 12.
     * Any value smaller than this results in
     * runtime error. */
    .max_entries = 4096 * 64,
};

struct bpf_map_def SEC("maps") task_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint64_t),
    .value_size = sizeof(union prov_elt),
    .max_entries = 4096, // TODO: set as big as possible; real size is dynamically adjusted
};

struct bpf_map_def SEC("maps") tmp_prov_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(union long_prov_elt),
    .max_entries = 4,
};

struct bpf_map_def SEC("maps") policy_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(struct capture_policy),
    .max_entries = 1,
};

struct bpf_map_def SEC("maps") prov_machine_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(union long_prov_elt),
    .max_entries = 1,
};

struct bpf_map_def SEC("maps") inode_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint64_t),
    .value_size = sizeof(union prov_elt),
    .max_entries = 4096, // TODO: set as big as possible; real size is dynamically adjusted
};

struct bpf_map_def SEC("maps") cred_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint64_t),
    .value_size = sizeof(union prov_elt),
    .max_entries = 4096, // TODO: set as big as possible; real size is dynamically adjusted
};

struct bpf_map_def SEC("maps") iattr_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint64_t),
    .value_size = sizeof(union prov_elt),
    .max_entries = 4096, // TODO: set as big as possible; real size is dynamically adjusted
};

struct bpf_map_def SEC("maps") msg_msg_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint64_t),
    .value_size = sizeof(union prov_elt),
    .max_entries = 4096, // TODO: set as big as possible; real size is dynamically adjusted
};

struct bpf_map_def SEC("maps") kern_ipc_perm_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint64_t),
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
