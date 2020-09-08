/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#ifndef __KERN_BPF_RELATION_H
#define __KERN_BPF_RELATION_H

/* Initialize common fields of a node's provenance */
static __always_inline void prov_init_relation(union prov_elt *prov, uint64_t type) {
    relation_identifier(prov).type=type;
    relation_identifier(prov).id = prov_next_id(RELATION_ID_INDEX);
    relation_identifier(prov).boot_id = prov_get_id(BOOT_ID_INDEX);
    relation_identifier(prov).machine_id = prov_get_id(MACHINE_ID_INDEX);
}

static __always_inline void record_terminate(uint64_t type, union prov_elt *node) {
    union prov_elt relation;
    __builtin_memset(&relation, 0, sizeof(union prov_elt));
    prov_init_relation(&relation, type);
    // set send node
    __builtin_memcpy(&relation.relation_info.snd, &node_identifier(node), sizeof(union prov_identifier));
    record_provenance(node);
    // update node version
    node_identifier(node).version++;
    // set rcv node
    __builtin_memcpy(&relation.relation_info.rcv, &node_identifier(node), sizeof(union prov_identifier));
    record_provenance(node);

    record_provenance(&relation);
}

#endif
