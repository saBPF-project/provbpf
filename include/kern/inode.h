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
#ifndef __KERN_BPF_INODE_H
#define __KERN_BPF_INODE_H

#include "kern/node.h"

#define S_PRIVATE	512	/* Inode is fs-internal */

#define IS_PRIVATE(inode)	((inode)->i_flags & S_PRIVATE)

#define is_inode_dir(inode)             S_ISDIR(inode->i_mode)
#define is_inode_socket(inode)          S_ISSOCK(inode->i_mode)
#define is_inode_file(inode)            S_ISREG(inode->i_mode)

static __always_inline void prov_update_inode(struct inode *inode, union prov_elt *prov) {
    prov->inode_info.uid = inode->i_uid.val;
    prov->inode_info.gid = inode->i_gid.val;
}

static __always_inline void prov_init_inode(struct inode *inode, union prov_elt *prov) {
    int index;
    for (index = 0; index < PROV_SBUUID_LEN; index++) {
      prov->inode_info.sb_uuid[index] = (inode->i_sb)->s_uuid.b[index];
    }
    prov->inode_info.secid = 0;
    prov->inode_info.mode = inode->i_mode;
    prov->inode_info.ino = inode->i_ino;
    prov_update_inode(inode, prov);
}

static union prov_elt* get_or_create_inode_prov(struct inode *inode) {
    uint64_t key;
    umode_t imode;
    int map_id = INODE_PERCPU_TMP;
    union prov_elt *prov_on_map, *prov_tmp;

    if (!inode)
      return NULL;

    key = get_key(inode);
    prov_on_map = bpf_map_lookup_elem(&inode_map, &key);
//    prov_on_map = bpf_inode_storage_get(&inode_map, inode, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);

    // inode provenance already being tracked
    if (prov_on_map) {
        // update the inode provenance in case it changed
        prov_update_inode(inode, prov_on_map);
    } else {
        prov_tmp = bpf_map_lookup_elem(&tmp_prov_elt_map, &map_id);
        if (!prov_tmp)
            return NULL;
        __builtin_memset(prov_tmp, 0, sizeof(union prov_elt));
        imode = inode->i_mode;
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

        prov_init_inode(inode, prov_tmp);
        bpf_map_update_elem(&inode_map, &key, prov_tmp, BPF_NOEXIST);
//        bpf_inode_storage_get(&inode_map, inode, prov_tmp, BPF_NOEXIST | BPF_LOCAL_STORAGE_GET_F_CREATE);
        prov_on_map = bpf_map_lookup_elem(&inode_map, &key);
//        prov_on_map = bpf_inode_storage_get(&inode_map, inode, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    }
    return prov_on_map;
}

#endif
