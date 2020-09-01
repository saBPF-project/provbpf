/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#ifndef __KERN_BPF_COMMON_H
#define __KERN_BPF_COMMON_H

#include "kern_bpf_maps.h"

static __always_inline uint64_t prov_next_id(uint32_t key)	{
    struct id_elem *val = bpf_map_lookup_elem(&ids_map, &key);
    if(!val)
        return 0;
    __sync_fetch_and_add(&val->id, 1);
    // this is wrong but cannot return value directly from __sync_fetch_and_add
    // someone needs to inv
    // Perhaps a lock is needed to avoid race conditions?
    return val->id;
}

static __always_inline uint64_t prov_get_id(uint32_t key) {
    struct id_elem *val = bpf_map_lookup_elem(&ids_map, &key);
    if(!val)
        return 0;
    return val->id;
}

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

#endif
