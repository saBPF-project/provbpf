/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#ifndef __KERN_BPF_MSG_MSG_H
#define __KERN_BPF_MSG_MSG_H

#include "kern_bpf_node.h"

static __always_inline union prov_elt* get_or_create_msg_msg_prov(struct msg_msg *msg) {
    if (!msg) {
      return NULL;
    }

    union prov_elt prov_tmp;
    uint64_t key = get_key(msg);
    union prov_elt *prov_on_map = bpf_map_lookup_elem(&msg_msg_map, &key);
    // provenance is already tracked
    if (prov_on_map) {
      // update the msg_msg's provenance since it may have changed
      prov_on_map->msg_msg_info.type = msg->m_type;
    } else {
      // a new msg_msg
      __builtin_memset(&prov_tmp, 0, sizeof(union prov_elt));
      prov_init_node(&prov_tmp, ENT_MSG);
      prov_tmp.msg_msg_info.type = msg->m_type;
      bpf_map_update_elem(&msg_msg_map, &key, &prov_tmp, BPF_NOEXIST);
      prov_on_map = bpf_map_lookup_elem(&msg_msg_map, &key);
    }
    return prov_on_map;
}

#endif
