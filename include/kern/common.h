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
#ifndef __KERN_BPF_COMMON_H
#define __KERN_BPF_COMMON_H

#include "kern/maps.h"
#include "shared/id.h"

// probably bad, find where it is defined
#define NULL 0

#define SIGIO		23

#define	SHM_RDONLY	010000	/* read-only access */

#define MAP_SHARED 					0x01
#define MAP_SHARED_VALIDATE 0x03
#define MAP_TYPE 	 					0x0f
#define MAY_EXEC		0x00000001
#define MAY_WRITE		0x00000002
#define MAY_READ		0x00000004
#define MAY_APPEND	0x00000008

#define PROT_READ  0x1
#define PROT_WRITE 0x2
#define PROT_EXEC  0x4

#define PTRACE_MODE_READ	0x01
#define PTRACE_MODE_ATTACH	0x02

#define FILE__EXECUTE           0x00000001UL
#define FILE__READ              0x00000002UL
#define FILE__APPEND            0x00000004UL
#define FILE__WRITE             0x00000008UL
#define DIR__SEARCH             0x00000010UL
#define DIR__WRITE              0x00000020UL
#define DIR__READ               0x00000040UL

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

#define XATTR_SECURITY_PREFIX	"security."
#define XATTR_PROVENANCE_SUFFIX "provenance"
#define XATTR_NAME_PROVENANCE XATTR_SECURITY_PREFIX XATTR_PROVENANCE_SUFFIX

#define AF_UNIX 1
#define AF_INET 2
#define PF_UNIX AF_UNIX
#define PF_INET AF_INET

#define clear_recorded(node) \
	__clear_recorded((union long_prov_elt *)node)
static inline void __clear_recorded(union long_prov_elt *node)
{
	node->msg_info.epoch = 0;
}

static __always_inline uint64_t prov_next_id(uint32_t key)	{
    struct id_elem *val = bpf_map_lookup_elem(&ids_map, &key);
    if(!val)
        return 0;
    __sync_fetch_and_add(&val->id, 1);
    // TODO: eBPF seems to have issue with __sync_fetch_and_add
    // TODO: we cannot obtain the return value of the function.
    // TODO: Perhaps we need a lock to avoid race conditions.
    return val->id;
}

static __always_inline uint64_t prov_get_id(uint32_t key) {
    struct id_elem *val = bpf_map_lookup_elem(&ids_map, &key);
    if(!val)
        return 0;
    return val->id;
}

static __always_inline void record_provenance(bool is_long_prov, void* prov){
	uint32_t policy_key = 0;
    struct capture_policy *prov_policy = bpf_map_lookup_elem(&policy_map, &policy_key);

	if (provenance_is_recorded((union prov_elt*)prov) && prov_policy && !prov_policy->should_duplicate)
		return;
	set_prov_recorded((union prov_elt*)prov);
	if (is_long_prov) {
      bpf_ringbuf_output(&r_buf, prov, sizeof(union long_prov_elt), 0);
    } else {
      bpf_ringbuf_output(&r_buf, prov, sizeof(union prov_elt), 0);
    }
}

/* it seems we have no choice */
static __always_inline uint64_t get_key(const void *obj) {
    return (uint64_t)obj;
}
/*
static __always_inline struct inode *SOCK_INODE(struct socket *socket)
{
	return &container_of(socket, struct socket_alloc, socket)->vfs_inode;
}
*/
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

#endif
