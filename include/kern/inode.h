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

#define __kernel_size_t
#define __kernel_fsid_t
#define __kernel_fd_set
#define statx_timestamp
#define statx
#include <linux/stat.h>
#undef __kernel_size_t
#undef __kernel_fsid_t
#undef __kernel_fd_set
#undef statx_timestamp
#undef statx

#include "kern/common.h"
#include "kern/node.h"
#include "kern/record.h"

#define MAY_EXEC		0x00000001
#define MAY_WRITE		0x00000002
#define MAY_READ		0x00000004
#define MAY_APPEND		0x00000008
#define MAY_ACCESS		0x00000010
#define MAY_OPEN		0x00000020
#define MAY_CHDIR		0x00000040

#define IS_PRIVATE(inode)	((inode)->i_flags & S_PRIVATE)

#define is_inode_dir(inode)             S_ISDIR(inode->i_mode)
#define is_inode_socket(inode)          S_ISSOCK(inode->i_mode)
#define is_inode_file(inode)            S_ISREG(inode->i_mode)

#define FILE__EXECUTE           0x00000001UL
#define FILE__READ              0x00000002UL
#define FILE__APPEND            0x00000004UL
#define FILE__WRITE             0x00000008UL
#define DIR__SEARCH             0x00000010UL
#define DIR__WRITE              0x00000020UL
#define DIR__READ               0x00000040UL

/*!
 * @brief Helper function to return permissions of a file/directory from mask.
 *
 * @param mode The mode of the inode.
 * @param mask The permission mask.
 * @return The permission of the file/directory/socket....
 *
 */
static inline uint32_t file_mask_to_perms(int mode, unsigned int mask)
{
	uint32_t av = 0;

	if (!S_ISDIR(mode)) {
		if (mask & MAY_EXEC)
			av |= FILE__EXECUTE;
		if (mask & MAY_READ)
			av |= FILE__READ;
		if (mask & MAY_APPEND)
			av |= FILE__APPEND;
		else if (mask & MAY_WRITE)
			av |= FILE__WRITE;
	} else {
		if (mask & MAY_EXEC)
			av |= DIR__SEARCH;
		if (mask & MAY_WRITE)
			av |= DIR__WRITE;
		if (mask & MAY_READ)
			av |= DIR__READ;
	}

	return av;
}

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
}

static union long_prov_elt* get_path_prov(struct inode *inode) {
    int map_id = PATH_PERCPU_LONG_TMP;
    union long_prov_elt *pprov;
    struct dentry *dentry = bpf_dentry_get(inode);
    if(!dentry)
        return NULL;

    pprov = bpf_map_lookup_elem(&long_tmp_prov_map, &map_id);
    if (!pprov)
      goto out;
    prov_init_node((union prov_elt *)pprov, ENT_PATH);

    // the function bellow crash (check error in kernel)
    // it may not be the rightway to do things
    // maybe use the dentry_path_raw within the helper using some allocated Helper
    // and then copying the results here?
    // the kernel error is not too clear about the problem 
    //bpf_dentry_path(dentry, pprov->file_name_info.name, PATH_MAX);
out:
    bpf_dentry_put(dentry);
    return pprov;
}

static union prov_elt* get_inode_prov(struct inode *inode) {
    umode_t imode;
    uint64_t type;
    struct provenance_holder *prov_holder;
    union prov_elt *prov;
    union long_prov_elt *pprov;

    if (!inode)
        return NULL;

    // we do not track directories
    if (is_inode_dir(inode))
        return NULL;

    prov_holder = bpf_inode_storage_get(&inode_storage_map, inode, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!prov_holder)
        return NULL;
    prov = &prov_holder->prov;

    if (!__set_initalized(prov)) {
        imode = inode->i_mode;
        if (S_ISREG(imode)) {
            // inode mode is regular file
            type = ENT_INODE_FILE;
        } else if (S_ISDIR(imode)) {
            // inode mode is directory
            type = ENT_INODE_DIRECTORY;
        } else if (S_ISCHR(imode)) {
            // inode mode is character device
            type = ENT_INODE_CHAR;
        } else if (S_ISBLK(imode)) {
            // inode mode is block device
            type = ENT_INODE_BLOCK;
        } else if (S_ISFIFO(imode)) {
            // inode mode is FIFO (named pipe)
            type = ENT_INODE_PIPE;
        } else if (S_ISLNK(imode)) {
            // inode mode is symbolic link
            type = ENT_INODE_LINK;
        } else if (S_ISSOCK(imode)) {
            // inode mode is socket
            type = ENT_INODE_SOCKET;
        } else {
            // inode mode is unknown
            type = ENT_INODE_UNKNOWN;
        }
        prov_init_node(prov, type);
        prov_init_inode(inode, prov);
    }
    if (provenance_is_opaque(prov))
        return NULL;
    prov_update_inode(inode, prov);
    if (!__set_name(prov) && is_inode_file(inode)) {
        pprov = get_path_prov(inode);
        if(!pprov)
            goto out;
        __record_relation_ls(RL_NAMED, pprov, prov, NULL, 0);
    }
out:
    return prov;
}

static union long_prov_elt* get_xattr_prov(const char *name, const void *value, size_t size) {
    int map_id = XATTR_PERCPU_LONG_TMP;
    union long_prov_elt *xprov = bpf_map_lookup_elem(&long_tmp_prov_map, &map_id);
    if (!xprov)
      return NULL;

    prov_init_node((union prov_elt *)xprov, ENT_XATTR);
    bpf_probe_read_kernel_str(xprov->xattr_info.name, PROV_XATTR_NAME_SIZE, name);
    xprov->xattr_info.size = size;
    return xprov;
}
#endif
