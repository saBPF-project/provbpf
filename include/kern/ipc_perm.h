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
#ifndef __KERN_BPF_KERN_IPC_PERM_H
#define __KERN_BPF_KERN_IPC_PERM_H

#include "kern/node.h"

static __always_inline union prov_elt* get_or_create_kern_ipc_perm_prov(struct kern_ipc_perm *shp) {
    if (!shp) {
      return NULL;
    }

    union prov_elt prov_tmp;
    uint64_t key = get_key(shp);
    union prov_elt *prov_on_map = bpf_map_lookup_elem(&kern_ipc_perm_map, &key);
    // provenance is already tracked
    if (prov_on_map) {
      // update the kern_ipc_perm's provenance since it may have changed
      prov_on_map->shm_info.mode = shp->mode;
    } else {
      // a new kern_ipc_perm
      __builtin_memset(&prov_tmp, 0, sizeof(union prov_elt));
      prov_init_node(&prov_tmp, ENT_SHM);
      prov_tmp.shm_info.mode = shp->mode;
      bpf_map_update_elem(&kern_ipc_perm_map, &key, &prov_tmp, BPF_NOEXIST);
      prov_on_map = bpf_map_lookup_elem(&kern_ipc_perm_map, &key);
    }
    return prov_on_map;
}

#endif
