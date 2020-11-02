/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#ifndef __KERN_BPF_FILTER_H
#define __KERN_BPF_FILTER_H

#define HIT_FILTER(filter, data) ((filter & data) != 0)

#define filter_node(node) \
        __filter_node((union long_prov_elt *)node)

static __always_inline bool __filter_node(union long_prov_elt *node) {
    if (provenance_is_opaque(node)) {
      return true;
    }
    return false;
}

#endif
