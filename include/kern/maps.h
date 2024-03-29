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
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	/* NOTE: The minimum size seems to be 1 << 12.
         * Any value smaller than this results in
         * runtime error. */
	__uint(max_entries, 1 << 18);
} r_buf SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, struct capture_policy);
	__uint(max_entries, 1);
} policy_map SEC(".maps");

#define RELATION_PERCPU_TMP 0

struct bpf_map_def SEC("maps") tmp_prov_elt_map = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(union prov_elt),
    .max_entries = 1,
};

#define ADDRESS_PERCPU_LONG_TMP 0
#define XATTR_PERCPU_LONG_TMP 1
#define PATH_PERCPU_LONG_TMP 2

struct bpf_map_def SEC("maps") long_tmp_prov_map = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(union long_prov_elt),
    .max_entries = 3,
};

struct bpf_map_def SEC("maps") prov_machine_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(union long_prov_elt),
    .max_entries = 1,
};

struct {
	__uint(type, BPF_MAP_TYPE_INODE_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct provenance_holder);
} inode_storage_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct provenance_holder);
} task_storage_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_CRED_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct provenance_holder);
} cred_storage_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_MSG_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct provenance_holder);
} msg_storage_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_IPC_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct provenance_holder);
} ipc_storage_map SEC(".maps");

struct bpf_map_def SEC("maps") ids_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(struct id_elem),
    .max_entries = ID_MAX_ENTRY,
};

#endif
