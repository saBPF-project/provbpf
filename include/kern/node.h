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
#ifndef __KERN_BPF_NODE_H
#define __KERN_BPF_NODE_H

/* Initialize common fields of a node's provenance */
static __always_inline void prov_init_node(union prov_elt *node, uint64_t type) {
    __builtin_memset(node, 0, sizeof(union prov_elt));
    node_identifier(node).type=type;
    node_identifier(node).id = prov_next_id(NODE_ID_INDEX);
    node_identifier(node).boot_id = prov_get_id(BOOT_ID_INDEX);
    node_identifier(node).machine_id = prov_get_id(MACHINE_ID_INDEX);
    set_initialized(node);
}

#endif
