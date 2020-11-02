/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#ifndef __KERN_BPF_FILTER_H
#define __KERN_BPF_FILTER_H

#define HIT_FILTER(filter, data) ((filter & data) != 0)

#define filter_node(node) \
        __filter_node((union long_prov_elt *)node)

static __always_inline bool __filter_node(union long_prov_elt *node) {
    int key = 0;
    struct capture_policy *prov_policy = bpf_map_lookup_elem(&policy_map, &key);
    if (!prov_policy)
      return false;

    if (!prov_policy->prov_enabled)
      return true;
    if (provenance_is_opaque(node))
      return true;
    if (HIT_FILTER(prov_policy->prov_node_filter, node_identifier(node).type))
      return true;
    return false;
}

#endif
