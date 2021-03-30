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
/*static __always_inline void prov_update_cred(struct task_struct *current_task,
                                             union prov_elt *prov) {
    // no more namespace tracking for now.
    // it looks we are copying data into pointer with no data
}*/

/* Create a provenance entry for a cred if it does not exist
 * and insert it into the @cred_storage_map; otherwise, updates its
 * existing provenance. Return either the new provenance entry
 * pointer or the updated provenance entry pointer. */
static __always_inline union prov_elt* update_cred_prov(
                                                const struct cred *cred,
                                                union prov_elt* prov) {
    if (!prov)
        return NULL;

    if (!provenance_is_initialized(prov))
        prov_init_node(prov, ENT_PROC);
    node_identifier(prov).version++;
    return prov;
}

#endif
