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

static __always_inline union prov_elt* get_ipc_prov(struct kern_ipc_perm *shp) {
    struct provenance_holder *prov_holder;
    union prov_elt* prov;

    if (!shp)
      return NULL;

    prov_holder = bpf_ipc_storage_get(&ipc_storage_map, shp, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!prov_holder)
      return NULL;
    prov = &prov_holder->prov;
    if (!__set_initalized(prov)) {
        prov_init_node(prov, ENT_SHM);
    }
    prov->shm_info.mode = shp->mode;
    return prov;
}
#endif
