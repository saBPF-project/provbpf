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

static __always_inline void iattr_init(union prov_elt *prov_iattr, struct iattr *iattr) {
    __builtin_memset(prov_iattr, 0, sizeof(union prov_elt));
    prov_init_node(prov_iattr, ENT_IATTR);
    prov_iattr->iattr_info.valid = iattr->ia_valid;
    prov_iattr->iattr_info.mode = iattr->ia_mode;
    prov_iattr->node_info.uid = iattr->ia_uid.val;
    prov_iattr->node_info.gid = iattr->ia_gid.val;
    prov_iattr->iattr_info.size = iattr->ia_size;
    prov_iattr->iattr_info.atime = iattr->ia_atime.tv_sec;
    prov_iattr->iattr_info.mtime = iattr->ia_mtime.tv_sec;
    prov_iattr->iattr_info.ctime = iattr->ia_ctime.tv_sec;
    return;
}

#endif
