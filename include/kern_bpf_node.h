/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#ifndef __KERN_BPF_NODE_H
#define __KERN_BPF_NODE_H

/* Initialize common fields of a node's provenance */
static __always_inline void prov_init_node(union long_prov_elt *prov, uint64_t type) {
    node_identifier(prov).type=type;
    node_identifier(prov).id = prov_next_id(NODE_ID_INDEX);
    node_identifier(prov).boot_id = prov_get_id(BOOT_ID_INDEX);
    node_identifier(prov).machine_id = prov_get_id(MACHINE_ID_INDEX);
}

#endif
