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
#ifndef __KERN_BPF_CRED_H
#define __KERN_BPF_CRED_H

#include "kern/node.h"

// Update fields in a cred's provenance
static __always_inline void __update_cred(const struct task_struct *task,
                                             union prov_elt *prov) {
    prov->proc_info.pid = task->tgid;
}

/* Create a provenance entry for a cred if it does not exist
 * and insert it into the @cred_storage_map; otherwise, updates its
 * existing provenance. Return either the new provenance entry
 * pointer or the updated provenance entry pointer. */
static __always_inline union prov_elt* __get_cred_prov(struct cred *cred, struct task_struct * task) {
    struct provenance_holder *prov_holder;
    union prov_elt* prov;

    if(!cred)
        return NULL;

    prov_holder = bpf_cred_storage_get(&cred_storage_map, cred, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!prov_holder)
        return NULL;
    prov = &prov_holder->prov;
    if (!__set_initalized(prov)) {
        prov_init_node(prov, ENT_PROC);
    }
    if (provenance_is_opaque(prov))
        return NULL;
    if(task)
        __update_cred(task, prov);
    return prov;
}

static __always_inline union prov_elt* get_cred_prov(struct cred *cred) {
    return __get_cred_prov(cred, NULL);
}


static __always_inline union prov_elt* get_cred_prov_from_task(struct task_struct * task) {
    if(!task)
        return NULL;
    return __get_cred_prov((struct cred *)task->real_cred, task);
}

#endif
