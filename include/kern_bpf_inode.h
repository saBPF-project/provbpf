/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#ifndef __KERN_BPF_INODE_H
#define __KERN_BPF_INODE_H

#include "kern_bpf_node.h"

#define S_IFMT  00170000
#define S_IFSOCK 0140000
#define S_IFLNK	 0120000
#define S_IFREG  0100000
#define S_IFBLK  0060000
#define S_IFDIR  0040000
#define S_IFCHR  0020000
#define S_IFIFO  0010000

#define S_ISLNK(m)	(((m) & S_IFMT) == S_IFLNK)
#define S_ISREG(m)	(((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m)	(((m) & S_IFMT) == S_IFDIR)
#define S_ISCHR(m)	(((m) & S_IFMT) == S_IFCHR)
#define S_ISBLK(m)	(((m) & S_IFMT) == S_IFBLK)
#define S_ISFIFO(m)	(((m) & S_IFMT) == S_IFIFO)
#define S_ISSOCK(m)	(((m) & S_IFMT) == S_IFSOCK)

static __always_inline void prov_update_inode(struct inode *inode, union prov_elt *prov) {
    prov->inode_info.uid = inode->i_uid.val;
    prov->inode_info.gid = inode->i_gid.val;
    prov->inode_info.mode = inode->i_mode;
    prov->inode_info.ino = inode->i_ino;
    int index;
    for (index = 0; index < PROV_SBUUID_LEN; index++) {
      prov->inode_info.sb_uuid[index] = inode->i_sb->s_uuid.b[index];
    }
}

static __always_inline union prov_elt* get_or_create_inode_prov(struct inode *inode, union prov_elt *new_prov) {
    uint64_t key = get_key(inode);
    union prov_elt *old_prov = bpf_map_lookup_elem(&inode_map, &key);

    if (old_prov) {
        prov_update_inode(inode, old_prov);
        return old_prov;
    } else {
        __builtin_memset(new_prov, 0, sizeof(union prov_elt));
        if (S_ISREG(inode->i_mode)) {
          // inode mode is regular file
          prov_init_node(new_prov, ENT_INODE_FILE);
        } else if (S_ISDIR(inode->i_mode)) {
          // inode mode is directory
          prov_init_node(new_prov, ENT_INODE_DIRECTORY);
        } else if (S_ISCHR(inode->i_mode)) {
          // inode mode is character device
          prov_init_node(new_prov, ENT_INODE_CHAR);
        } else if (S_ISBLK(inode->i_mode)) {
          // inode mode is block device
          prov_init_node(new_prov, ENT_INODE_BLOCK);
        } else if (S_ISFIFO(inode->i_mode)) {
          // inode mode is FIFO (named pipe)
          prov_init_node(new_prov, ENT_INODE_PIPE);
        } else if (S_ISLNK(inode->i_mode)) {
          // inode mode is symbolic link
          prov_init_node(new_prov, ENT_INODE_LINK);
        } else if (S_ISSOCK(inode->i_mode)) {
          // inode mode is socket
          prov_init_node(new_prov, ENT_INODE_SOCKET);
        } else {
          // inode mode is unknown
          prov_init_node(new_prov, ENT_INODE_UNKNOWN);
        }

        prov_update_inode(inode, new_prov);
        bpf_map_update_elem(&inode_map, &key, new_prov, BPF_NOEXIST);
        return new_prov;
    }
}

#endif