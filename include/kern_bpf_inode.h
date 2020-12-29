/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#ifndef __KERN_BPF_INODE_H
#define __KERN_BPF_INODE_H

#include "kern_bpf_node.h"

#define S_PRIVATE	512	/* Inode is fs-internal */

#define IS_PRIVATE(inode)	((inode)->i_flags & S_PRIVATE)

#define is_inode_dir(inode)             S_ISDIR(inode->i_mode)
#define is_inode_socket(inode)          S_ISSOCK(inode->i_mode)
#define is_inode_file(inode)            S_ISREG(inode->i_mode)

static __always_inline void prov_update_inode(struct inode *inode, union prov_elt *prov) {
    bpf_probe_read(&prov->inode_info.uid, sizeof(prov->inode_info.uid), &inode->i_uid.val);
    bpf_probe_read(&prov->inode_info.gid, sizeof(prov->inode_info.gid), &inode->i_gid.val);
    bpf_probe_read(&prov->inode_info.mode, sizeof(prov->inode_info.mode), &inode->i_mode);
    bpf_probe_read(&prov->inode_info.ino, sizeof(prov->inode_info.ino), &inode->i_ino);

    int index;
    struct super_block *isb;
    bpf_probe_read(&isb, sizeof(isb), &inode->i_sb);
    for (index = 0; index < PROV_SBUUID_LEN; index++) {
      bpf_probe_read(&prov->inode_info.sb_uuid[index], sizeof(prov->inode_info.sb_uuid[index]), &isb->s_uuid.b[index]);
    }
    prov->inode_info.secid = 0;
}

static __always_inline union prov_elt* get_or_create_inode_prov(struct inode *inode) {
    if (!inode) {
      return NULL;
    }

    int map_id = 0;
    union prov_elt *prov_tmp = bpf_map_lookup_elem(&tmp_prov_elt_map, &map_id);
    if (!prov_tmp)
        return NULL;
    uint64_t key = get_key(inode);
    union prov_elt *prov_on_map = bpf_map_lookup_elem(&inode_map, &key);

    if (prov_on_map) {
        // update the inode provenance in case it changed
        prov_update_inode(inode, prov_on_map);
    } else {
        // __builtin_memset(&prov_tmp, 0, sizeof(union prov_elt));
        umode_t imode;
        bpf_probe_read(&imode, sizeof(imode), &inode->i_mode);
        if (S_ISREG(imode)) {
          // inode mode is regular file
          prov_init_node(prov_tmp, ENT_INODE_FILE);
        } else if (S_ISDIR(imode)) {
          // inode mode is directory
          prov_init_node(prov_tmp, ENT_INODE_DIRECTORY);
        } else if (S_ISCHR(imode)) {
          // inode mode is character device
          prov_init_node(prov_tmp, ENT_INODE_CHAR);
        } else if (S_ISBLK(imode)) {
          // inode mode is block device
          prov_init_node(prov_tmp, ENT_INODE_BLOCK);
        } else if (S_ISFIFO(imode)) {
          // inode mode is FIFO (named pipe)
          prov_init_node(prov_tmp, ENT_INODE_PIPE);
        } else if (S_ISLNK(imode)) {
          // inode mode is symbolic link
          prov_init_node(prov_tmp, ENT_INODE_LINK);
        } else if (S_ISSOCK(imode)) {
          // inode mode is socket
          prov_init_node(prov_tmp, ENT_INODE_SOCKET);
        } else {
          // inode mode is unknown
          prov_init_node(prov_tmp, ENT_INODE_UNKNOWN);
        }

        prov_update_inode(inode, prov_tmp);
        bpf_map_update_elem(&inode_map, &key, prov_tmp, BPF_NOEXIST);
        prov_on_map = bpf_map_lookup_elem(&inode_map, &key);
    }
    return prov_on_map;
}

#endif
