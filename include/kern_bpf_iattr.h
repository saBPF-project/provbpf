/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#ifndef __KERN_BPF_IATTR_H
#define __KERN_BPF_IATTR_H

#include "kern_bpf_node.h"

static __always_inline void prov_update_iattr(struct iattr *iattr,
                                              union long_prov_elt *prov) {
    prov->iattr_info.valid = iattr->ia_valid;
    prov->iattr_info.mode = iattr->ia_mode;
    prov->node_info.uid = iattr->ia_uid.val;
    prov->node_info.gid = iattr->ia_gid.val;
    prov->iattr_info.size = iattr->ia_size;
    prov->iattr_info.atime = iattr->ia_atime.tv_sec;
    prov->iattr_info.mtime = iattr->ia_mtime.tv_sec;
    prov->iattr_info.ctime = iattr->ia_ctime.tv_sec;
}

static __always_inline union long_prov_elt* get_or_create_iattr_prov(struct iattr *iattr) {
    union long_prov_elt *prov_tmp;
    uint64_t key = get_key(iattr);
    union long_prov_elt *prov_on_map = bpf_map_lookup_elem(&iattr_map, &key);

    if (prov_on_map) {
      prov_update_iattr(iattr, prov_on_map);
    } else {
      int map_id = 0;
      prov_tmp = bpf_map_lookup_elem(&tmp_prov_map, &map_id);
      if (!prov_tmp) {
        return 0;
      }
      prov_init_node(prov_tmp, ENT_IATTR);
      prov_update_iattr(iattr, prov_tmp);
      bpf_map_update_elem(&iattr_map, &key, prov_tmp, BPF_NOEXIST);
      prov_on_map = bpf_map_lookup_elem(&iattr_map, &key);
    }
    return prov_on_map;
}

#endif
