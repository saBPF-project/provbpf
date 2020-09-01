/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#ifndef __KERN_BPF_NODE_H
#define __KERN_BPF_NODE_H

static __always_inline void prov_init_node(union prov_elt *prov, uint64_t type) {
    prov->node_info.identifier.node_id.type=type;
    prov->node_info.identifier.node_id.id = prov_next_id(NODE_ID_INDEX);
    prov->node_info.identifier.node_id.boot_id = prov_get_id(BOOT_ID_INDEX);
    prov->node_info.identifier.node_id.machine_id = prov_get_id(MACHINE_ID_INDEX);
}

#endif
