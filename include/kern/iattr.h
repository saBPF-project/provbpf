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
#ifndef __KERN_BPF_IATTR_H
#define __KERN_BPF_IATTR_H

#include "kern/node.h"

static __always_inline void prov_update_iattr(struct iattr *iattr,
                                              union prov_elt *prov) {
    prov->iattr_info.valid = iattr->ia_valid;
    prov->iattr_info.mode = iattr->ia_mode;
    prov->node_info.uid = iattr->ia_uid.val;
    prov->node_info.gid = iattr->ia_gid.val;
    prov->iattr_info.size = iattr->ia_size;
    prov->iattr_info.atime = iattr->ia_atime.tv_sec;
    prov->iattr_info.mtime = iattr->ia_mtime.tv_sec;
    prov->iattr_info.ctime = iattr->ia_ctime.tv_sec;
}

static __always_inline union prov_elt* get_or_create_iattr_prov(struct iattr *iattr) {
    union prov_elt prov_tmp;
    uint64_t key = get_key(iattr);
    union prov_elt *prov_on_map = bpf_map_lookup_elem(&iattr_map, &key);

    if (prov_on_map) {
      prov_update_iattr(iattr, prov_on_map);
    } else {
      prov_init_node(&prov_tmp, ENT_IATTR);
      prov_update_iattr(iattr, &prov_tmp);
      bpf_map_update_elem(&iattr_map, &key, &prov_tmp, BPF_NOEXIST);
      prov_on_map = bpf_map_lookup_elem(&iattr_map, &key);
    }
    return prov_on_map;
}

#endif
