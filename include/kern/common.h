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
#ifndef __KERN_BPF_COMMON_H
#define __KERN_BPF_COMMON_H

#include "kern/maps.h"
#include "shared/id.h"

#define NULL ((void *)0)

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

static __always_inline struct bpf_spin_lock* prov_lock(union prov_elt* ptr) {
    return &(container_of(ptr, struct provenance_holder, prov)->lock);
}

static __always_inline bool __set_initalized(union prov_elt* prov) {
    bool is_initialized;
    bpf_spin_lock(prov_lock(prov));
    is_initialized = provenance_is_initialized(prov);
    if (!is_initialized)
        set_initialized(prov);
    bpf_spin_unlock(prov_lock(prov));
    return is_initialized;
}

static __always_inline bool __set_name(union prov_elt* prov) {
    bool is_named;
    bpf_spin_lock(prov_lock(prov));
    is_named = provenance_is_named(prov);
    if (!is_named)
        set_named(prov);
    bpf_spin_unlock(prov_lock(prov));
    return is_named;
}
#endif
