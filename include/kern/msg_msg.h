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
#ifndef __KERN_BPF_MSG_MSG_H
#define __KERN_BPF_MSG_MSG_H

#include "kern/node.h"

static __always_inline union prov_elt* get_msg_prov(struct msg_msg *msg) {
    struct provenance_holder *prov_holder;
    union prov_elt* prov;

    if(!msg)
        return NULL;

    prov_holder = bpf_msg_storage_get(&msg_storage_map, msg, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!prov_holder)
        return NULL;
    prov = &prov_holder->prov;
    if (!__set_initalized(prov)) {
        prov_init_node(prov, ENT_MSG);
        prov->msg_msg_info.type = msg->m_type;
    }
    return prov;
}
#endif
