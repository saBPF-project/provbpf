/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#ifndef __KERN_BPF_COMMON_H
#define __KERN_BPF_COMMON_H

#include "kern_bpf_maps.h"

// probably bad, find where it is defined
#define NULL 0

#define PTRACE_MODE_READ	0x01
#define PTRACE_MODE_ATTACH	0x02
#define XATTR_SECURITY_PREFIX	"security."
#define XATTR_PROVENANCE_SUFFIX "provenance"
#define XATTR_NAME_PROVENANCE XATTR_SECURITY_PREFIX XATTR_PROVENANCE_SUFFIX

#define clear_recorded(node) \
	__clear_recorded((union long_prov_elt *)node)
static inline void __clear_recorded(union long_prov_elt *node)
{
	node->msg_info.epoch = 0;
}

static __always_inline uint64_t prov_next_id(uint32_t key)	{
    struct id_elem *val = bpf_map_lookup_elem(&ids_map, &key);
    if(!val)
        return 0;
    __sync_fetch_and_add(&val->id, 1);
    // TODO: eBPF seems to have issue with __sync_fetch_and_add
    // TODO: we cannot obtain the return value of the function.
    // TODO: Perhaps we need a lock to avoid race conditions.
    return val->id;
}

static __always_inline uint64_t prov_get_id(uint32_t key) {
    struct id_elem *val = bpf_map_lookup_elem(&ids_map, &key);
    if(!val)
        return 0;
    return val->id;
}

static __always_inline void record_provenance(bool is_long_prov, void* prov){
    if (is_long_prov) {
      bpf_ringbuf_output(&r_buf, prov, sizeof(union long_prov_elt), 0);
    } else {
      bpf_ringbuf_output(&r_buf, prov, sizeof(union prov_elt), 0);
    }
}

static __always_inline uint64_t u64_max(uint64_t a, uint64_t b) {
    return (a > b) ? a : b;
}

/* it seems we have no choice */
static __always_inline uint64_t get_key(const void *obj) {
    return (uint64_t)obj;
}

#endif
