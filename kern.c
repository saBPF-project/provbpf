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
#include "kern/vmlinux.h"

#include <linux/libc-compat.h>
#include <linux/mman.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <linux/limits.h>

#include "shared/prov_struct.h"
#include "shared/prov_types.h"
#include "shared/id.h"
#include "shared/policy.h"

#include "kern/maps.h"
#include "kern/common.h"
#include "kern/node.h"
#include "kern/task.h"
#include "kern/inode.h"
#include "kern/cred.h"
#include "kern/msg_msg.h"
#include "kern/ipc_perm.h"
#include "kern/record.h"
#include "kern/net.h"

char _license[] SEC("license") = "GPL";

SEC("lsm/task_alloc")
int BPF_PROG(task_alloc, struct task_struct *task, unsigned long clone_flags) {
  struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
  union prov_elt *tprov, *tnprov;

  if (!current_task)
      return 0;

  tprov = get_task_prov(current_task);
  if (!tprov)
      return 0;

  tnprov = get_task_prov(task);
  if(!tnprov)
      return 0;

  informs(RL_CLONE, tprov, tnprov, NULL, clone_flags);
  return 0;
}

SEC("lsm/task_free")
int BPF_PROG(task_free, struct task_struct *task) {
  union prov_elt *tprov;

  tprov = get_task_prov(task);
  if (!tprov) // something is wrong
      return 0;

  /* Record task terminate */
  record_terminate(RL_TERMINATE_TASK, tprov);
  return 0;
}

SEC("lsm/task_fix_setuid")
int BPF_PROG(task_fix_setuid, struct cred *new, const struct cred *old, int flags) {
  union prov_elt *cprov, *oprov, *tprov;
  struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();

	cprov = get_cred_prov(new);
  if (!cprov)
    return 0;

	oprov = get_cred_prov((struct cred*)old);
  if (!oprov)
    return 0;

	tprov = get_task_prov(current_task);
  if (!tprov)
    return 0;

  generates(RL_SETUID, current_task, oprov, tprov, cprov, NULL, flags);
  return 0;
}

SEC("lsm/task_fix_setgid")
int BPF_PROG(task_fix_setgid, struct cred *new, const struct cred *old, int flags) {
  union prov_elt *cprov, *oprov, *tprov;
  struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();

	tprov = get_task_prov(current_task);
	if (!tprov)
		return 0;

	cprov = get_cred_prov(new);
	if (!cprov)
	  return 0;

	oprov = get_cred_prov((struct cred*)old);
	if (!oprov)
	  return 0;

	generates(RL_SETGID, current_task, oprov, tprov, cprov, NULL, flags);
	return 0;
}

SEC("lsm/task_getpgid")
int BPF_PROG(task_getpgid, struct task_struct *p) {
	union prov_elt *nprov, *tprov, *cprov;
	struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();

	tprov = get_task_prov(current_task);
	if (!tprov)
		return 0;

	cprov = get_cred_prov_from_task(current_task);
	if (!cprov)
		return 0;

	nprov = get_cred_prov_from_task(p);
  if (!nprov)
    return 0;

  uses(RL_GETGID, current_task, nprov, tprov, cprov, NULL, 0);
  return 0;
}

SEC("lsm/cred_free")
int BPF_PROG(cred_free, struct cred *cred) {
    union prov_elt *cprov;

    cprov = get_cred_prov(cred);
    if (!cprov)
      return 0;
    // Record cred freed
    record_terminate(RL_TERMINATE_PROC, cprov);
    return 0;
}

SEC("lsm/inode_free_security")
int BPF_PROG(inode_free_security, struct inode *inode) {
    union prov_elt *iprov;

    if (is_inode_dir(inode))
        return 0;

    iprov = get_inode_prov(inode);
    if(!iprov) // something is wrong
        return 0;

    /* Record inode freed */
    record_terminate(RL_FREED, iprov);
    return 0;
}

SEC("lsm/inode_permission")
int BPF_PROG(inode_permission, struct inode *inode, int mask) {
    struct task_struct *current_task;
    union prov_elt *cprov, *tprov, *iprov;

    if (is_inode_dir(inode))
        return 0;

    if (!mask)
      return 0;

    current_task = (struct task_struct *)bpf_get_current_task_btf();
    if (!current_task)
        return 0;

    tprov = get_task_prov(current_task);
    if (!tprov)
      return 0;

    cprov = get_cred_prov_from_task(current_task);
    if (!cprov)
      return 0;

    iprov = get_inode_prov(inode);
    if (!iprov)
      return 0;

    uses(RL_PERM, current_task, iprov, tprov, cprov, NULL, mask);
    return 0;
}

SEC("lsm/inode_setattr")
int BPF_PROG(inode_setattr, struct dentry *dentry, struct iattr *attr) {
    struct task_struct *current_task;
    union prov_elt *cprov, *tprov, *iprov;

    if(!dentry)
        return 0;

    if (is_inode_dir(dentry->d_inode))
        return 0;

    current_task = (struct task_struct *)bpf_get_current_task_btf();
    if (!current_task)
        return 0;

    tprov = get_task_prov(current_task);
    if (!tprov)
      return 0;

    cprov = get_cred_prov_from_task(current_task);
    if (!cprov)
      return 0;

    iprov = get_inode_prov(dentry->d_inode);
    if (!iprov)
      return 0;

    generates(RL_SETATTR, current_task, cprov, tprov, iprov, NULL, 0);
    return 0;
}

SEC("lsm/inode_getattr")
int BPF_PROG(inode_getattr, const struct path *path) {
    struct task_struct *current_task;
    union prov_elt *cprov, *tprov, *iprov;

    if(!path)
        return 0;

    if (is_inode_dir(path->dentry->d_inode))
        return 0;

    current_task = (struct task_struct *)bpf_get_current_task_btf();
    if (!current_task)
        return 0;

    tprov = get_task_prov(current_task);
    if (!tprov)
      return 0;

    cprov = get_cred_prov_from_task(current_task);
    if (!cprov)
      return 0;

    iprov = get_inode_prov(path->dentry->d_inode);
    if (!iprov)
      return 0;

    uses(RL_GETATTR, current_task, iprov, tprov, cprov, NULL, 0);
    return 0;
}

SEC("lsm/inode_post_setxattr")
int BPF_PROG(inode_post_setxattr, struct dentry *dentry, const char *name,const void *value, size_t size, int flags) {
    struct task_struct *current_task;
    union prov_elt *cprov, *tprov, *iprov;
    static union long_prov_elt* xprov;

    if(!dentry)
        return 0;

    if (is_inode_dir(dentry->d_inode))
        return 0;

    current_task = (struct task_struct *)bpf_get_current_task_btf();
    if (!current_task)
        return 0;

    tprov = get_task_prov(current_task);
    if (!tprov)
        return 0;

    cprov = get_cred_prov_from_task(current_task);
    if (!cprov)
        return 0;

    iprov = get_inode_prov(dentry->d_inode);
    if (!iprov)
        return 0;

    xprov = get_xattr_prov(name, value, size);
    if (!xprov)
        return 0;

    record_write_xattr(RL_SETXATTR, cprov, tprov, xprov, iprov, flags);
    return 0;
}

SEC("lsm/inode_getxattr")
int BPF_PROG(inode_getxattr, struct dentry *dentry, const char *name) {
    struct task_struct *current_task;
    union prov_elt *cprov, *tprov, *iprov;
    static union long_prov_elt* xprov;

    if(!dentry)
        return 0;

    if (is_inode_dir(dentry->d_inode))
        return 0;

    current_task = (struct task_struct *)bpf_get_current_task_btf();
    if (!current_task)
        return 0;

    tprov = get_task_prov(current_task);
    if (!tprov)
        return 0;

    cprov = get_cred_prov_from_task(current_task);
    if (!cprov)
        return 0;

    iprov = get_inode_prov(dentry->d_inode);
    if (!iprov)
        return 0;

    xprov = get_xattr_prov(name, NULL, 0);
    if (!xprov)
        return 0;

    record_read_xattr(RL_GETXATTR, iprov, xprov, tprov, cprov);
    return 0;
}

SEC("lsm/inode_removexattr")
int BPF_PROG(inode_removexattr, struct dentry *dentry, const char *name) {
    struct task_struct *current_task;
    union prov_elt *cprov, *tprov, *iprov;
    static union long_prov_elt* xprov;

    if(!dentry)
        return 0;

    if (is_inode_dir(dentry->d_inode))
        return 0;

    current_task = (struct task_struct *)bpf_get_current_task_btf();
    if (!current_task)
        return 0;

    tprov = get_task_prov(current_task);
    if (!tprov)
        return 0;

    cprov = get_cred_prov_from_task(current_task);
    if (!cprov)
        return 0;

    iprov = get_inode_prov(dentry->d_inode);
    if (!iprov)
        return 0;

    xprov = get_xattr_prov(name, NULL, 0);
    if (!xprov)
        return 0;

    record_write_xattr(RL_RMVXATTR, cprov, tprov, xprov, iprov, 0);
    return 0;
}

SEC("lsm/inode_listxattr")
int BPF_PROG(inode_listxattr, struct dentry *dentry) {
    struct task_struct *current_task;
    union prov_elt *cprov, *tprov, *iprov;

    if(!dentry)
        return 0;

    if (is_inode_dir(dentry->d_inode))
        return 0;

    current_task = (struct task_struct *)bpf_get_current_task_btf();
    if (!current_task)
        return 0;

    tprov = get_task_prov(current_task);
    if (!tprov)
        return 0;

    cprov = get_cred_prov_from_task(current_task);
    if (!cprov)
        return 0;

    iprov = get_inode_prov(dentry->d_inode);
    if (!iprov)
        return 0;

    uses(RL_LSTXATTR, current_task, iprov, tprov, cprov, NULL, 0);
    return 0;
}

SEC("lsm/file_permission")
int BPF_PROG(file_permission, struct file *file, int mask) {
    struct task_struct *current_task;
    union prov_elt *tprov, *cprov, *iprov;
    uint32_t perms;

    if (is_inode_dir(file->f_inode))
        return 0;

    current_task = (struct task_struct *)bpf_get_current_task_btf();
    tprov = get_task_prov(current_task);
    if (!tprov)
        return 0;

    cprov = get_cred_prov_from_task(current_task);
    if (!cprov)
        return 0;

    iprov = get_inode_prov(file->f_inode);
    if (!iprov)
      return 0;

    perms = file_mask_to_perms((file->f_inode)->i_mode, mask);

    if (is_inode_socket(file->f_inode)) {
        if ((perms & (FILE__WRITE | FILE__APPEND)) != 0)
            generates(RL_SND, current_task, cprov, tprov, iprov, file, mask);
        if ((perms & (FILE__READ)) != 0)
            uses(RL_RCV, current_task, iprov, tprov, cprov, file, mask);
    } else {
        if ((perms & (FILE__WRITE | FILE__APPEND)) != 0)
            generates(RL_WRITE, current_task, cprov, tprov, iprov, file, mask);
        if ((perms & (FILE__READ)) != 0)
            uses(RL_READ, current_task, iprov, tprov, cprov, file, mask);
        if ((perms & (FILE__EXECUTE)) != 0) {
            if (provenance_is_opaque(iprov)) {
                set_opaque(cprov);
            } else {
                derives(RL_EXEC, iprov, cprov, file, mask);
            }
        }
    }
    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(file_open, struct file *file) {
    union prov_elt *tprov, *cprov, *iprov;
    struct task_struct *current_task;

    if (is_inode_dir(file->f_inode))
        return 0;

    current_task = (struct task_struct *)bpf_get_current_task_btf();
    tprov = get_task_prov(current_task);
    if (!tprov)
        return 0;

    cprov = get_cred_prov_from_task(current_task);
    if (!cprov)
        return 0;

    iprov = get_inode_prov(file->f_inode);
    if (!iprov)
      return 0;

    uses(RL_OPEN, current_task, iprov, tprov, cprov, file, 0);
    return 0;
}

SEC("lsm/file_receive")
int BPF_PROG(file_receive, struct file *file) {
    union prov_elt *tprov, *cprov, *iprov;
    struct task_struct *current_task;

    if (is_inode_dir(file->f_inode))
        return 0;

    current_task = (struct task_struct *)bpf_get_current_task_btf();
    tprov = get_task_prov(current_task);
    if (!tprov)
        return 0;

    cprov = get_cred_prov_from_task(current_task);
    if (!cprov)
        return 0;

    iprov = get_inode_prov(file->f_inode);
    if (!iprov)
      return 0;

    uses(RL_FILE_RCV, current_task, iprov, tprov, cprov, file, 0);
    return 0;
}

SEC("lsm/file_lock")
int BPF_PROG(file_lock, struct file *file, unsigned int cmd) {
    union prov_elt *tprov, *cprov, *iprov;
    struct task_struct *current_task;

    if (is_inode_dir(file->f_inode))
        return 0;

    current_task = (struct task_struct *)bpf_get_current_task_btf();
    tprov = get_task_prov(current_task);
    if (!tprov)
        return 0;

    cprov = get_cred_prov_from_task(current_task);
    if (!cprov)
        return 0;

    iprov = get_inode_prov(file->f_inode);
    if (!iprov)
      return 0;

    generates(RL_FILE_LOCK, current_task, cprov, tprov, iprov, file, cmd);
    return 0;
}

SEC("lsm/file_ioctl")
int BPF_PROG(file_ioctl, struct file *file, unsigned int cmd, unsigned long arg) {
    union prov_elt *tprov, *cprov, *iprov;
    struct task_struct *current_task;

    if (is_inode_dir(file->f_inode))
        return 0;

    current_task = (struct task_struct *)bpf_get_current_task_btf();
    tprov = get_task_prov(current_task);
    if (!tprov)
        return 0;

    cprov = get_cred_prov_from_task(current_task);
    if (!cprov)
        return 0;

    iprov = get_inode_prov(file->f_inode);
    if (!iprov)
      return 0;

    generates(RL_WRITE_IOCTL, current_task, cprov, tprov, iprov, file, cmd);
    uses(RL_READ_IOCTL, current_task, iprov, tprov, cprov, file, cmd);
    return 0;
}

SEC("lsm/mmap_file")
int BPF_PROG(mmap_file, struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags) {
    union prov_elt *tprov, *cprov, *iprov;
    struct task_struct *current_task;
    uint64_t type;

    if (!file)
        return 0;
    if (is_inode_dir(file->f_inode))
        return 0;
    iprov = get_inode_prov(file->f_inode);
    if (!iprov)
        return 0;

    current_task = (struct task_struct *)bpf_get_current_task_btf();
    if (!current_task)
        return 0;
    tprov = get_task_prov(current_task);
    if (!tprov)
        return 0;

    cprov = get_cred_prov_from_task(current_task);
    if (!cprov)
      return 0;

    if ((flags & MAP_TYPE) == MAP_SHARED || (flags & MAP_TYPE) == MAP_SHARED_VALIDATE) {
      type = RL_MMAP_PRIVATE;
    } else {
      type = RL_MMAP;
    }
    uses(type, current_task, iprov, tprov, cprov, file, prot);
    return 0;
}

SEC("lsm/socket_post_create")
int BPF_PROG(socket_post_create, struct socket *sock, int family, int type, int protocol, int kern) {
    union prov_elt *tprov, *cprov, *iprov;
    struct task_struct *current_task;
    union flags {
        struct {
            int type;
            int protocol;
        } values;
        uint64_t flags;
    } flags;

    if (kern)
      return 0;

    current_task = (struct task_struct *)bpf_get_current_task_btf();
    if (!current_task)
        return 0;
    tprov = get_task_prov(current_task);
    if (!tprov)
      return 0;

    cprov = get_cred_prov_from_task(current_task);
    if (!cprov)
      return 0;

    iprov = get_inode_prov((struct inode *)bpf_inode_from_sock(sock));
    if (!iprov)
      return 0;

    // pass type and protocol via the flag entry in provennance
    flags.values.type = type;
    flags.values.protocol = protocol;

    generates(RL_SOCKET_CREATE, current_task, cprov, tprov, iprov, NULL, flags.flags);
    return 0;
}

SEC("lsm/socket_bind")
int BPF_PROG(socket_bind, struct socket *sock, struct sockaddr *address, int addrlen) {
    union prov_elt *tprov, *cprov, *iprov;
    struct task_struct *current_task;

    current_task = (struct task_struct *)bpf_get_current_task_btf();
    if (!current_task)
        return 0;
    tprov = get_task_prov(current_task);
    if (!tprov)
      return 0;

    cprov = get_cred_prov_from_task(current_task);
    if (!cprov)
      return 0;

    iprov = get_inode_prov((struct inode *)bpf_inode_from_sock(sock));
    if (!iprov)
      return 0;

    record_address(address, addrlen, iprov);
    generates(RL_BIND, current_task, cprov, tprov, iprov, NULL, 0);
    return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(socket_connect, struct socket *sock, struct sockaddr *address, int addrlen) {
    union prov_elt *tprov, *cprov, *iprov;
    struct task_struct *current_task;

    current_task = (struct task_struct *)bpf_get_current_task_btf();
    if (!current_task)
        return 0;
    tprov = get_task_prov(current_task);
    if (!tprov)
      return 0;

    cprov = get_cred_prov_from_task(current_task);
    if (!cprov)
      return 0;

    iprov = get_inode_prov((struct inode *)bpf_inode_from_sock(sock));
    if (!iprov)
      return 0;

    record_address(address, addrlen, iprov);
    generates(RL_CONNECT, current_task, cprov, tprov, iprov, NULL, 0);
    return 0;
}

SEC("lsm/socket_listen")
int BPF_PROG(socket_listen, struct socket *sock, int backlog) {
    union prov_elt *tprov, *cprov, *iprov;
    struct task_struct *current_task;

    current_task = (struct task_struct *)bpf_get_current_task_btf();
    if (!current_task)
        return 0;
    tprov = get_task_prov(current_task);
    if (!tprov)
      return 0;

    cprov = get_cred_prov_from_task(current_task);
    if (!cprov)
      return 0;

    iprov = get_inode_prov((struct inode *)bpf_inode_from_sock(sock));
    if (!iprov)
      return 0;

    generates(RL_LISTEN, current_task, cprov, tprov, iprov, NULL, backlog);
    return 0;
}

SEC("lsm/socket_accept")
int BPF_PROG(socket_accept, struct socket *sock, struct socket *newsock) {
    union prov_elt *tprov, *cprov, *iprov, *niprov;
    struct task_struct *current_task;

    current_task = (struct task_struct *)bpf_get_current_task_btf();
    if (!current_task)
        return 0;
    tprov = get_task_prov(current_task);
    if (!tprov)
      return 0;

    cprov = get_cred_prov_from_task(current_task);
    if (!cprov)
      return 0;

    iprov = get_inode_prov((struct inode *)bpf_inode_from_sock(sock));
    if (!iprov)
      return 0;

    niprov = get_inode_prov((struct inode *)bpf_inode_from_sock(sock));
    if (!niprov)
      return 0;

    derives(RL_ACCEPT_SOCKET, iprov, niprov, NULL, 0);
    uses(RL_ACCEPT, current_task, niprov, tprov, cprov, NULL, 0);
    return 0;
}

SEC("lsm/msg_msg_alloc_security")
int BPF_PROG(msg_msg_alloc_security, struct msg_msg *msg) {
    union prov_elt *tprov, *cprov, *mprov;
    struct task_struct *current_task;

    current_task = (struct task_struct *)bpf_get_current_task_btf();
    if (!current_task)
        return 0;
    tprov = get_task_prov(current_task);
    if (!tprov)
      return 0;

    cprov = get_cred_prov_from_task(current_task);
    if (!cprov)
      return 0;

    mprov = get_msg_prov(msg);
    if (!mprov)
        return 0;

    generates(RL_MSG_CREATE, current_task, cprov, tprov, mprov, NULL, 0);
    return 0;
}

SEC("lsm/msg_msg_free_security")
int BPF_PROG(msg_msg_free_security, struct msg_msg *msg) {
    union prov_elt *mprov;

    mprov = get_msg_prov(msg);
    if (!mprov)
        return 0;

    record_terminate(RL_FREED, mprov);
    return 0;
}

SEC("lsm/msg_queue_msgsnd")
int BPF_PROG(msg_queue_msgsnd, struct kern_ipc_perm *msq, struct msg_msg *msg, int msqflg) {
    union prov_elt *tprov, *cprov, *mprov;
    struct task_struct *current_task;

    current_task = (struct task_struct *)bpf_get_current_task_btf();
    if (!current_task)
        return 0;
    tprov = get_task_prov(current_task);
    if (!tprov)
      return 0;

    cprov = get_cred_prov_from_task(current_task);
    if (!cprov)
      return 0;

    mprov = get_msg_prov(msg);
    if (!mprov)
        return 0;

    generates(RL_SND_MSG_Q, current_task, cprov, tprov, mprov, NULL, msqflg);
    return 0;
}

SEC("lsm/msg_queue_msgrcv")
int BPF_PROG(msg_queue_msgrcv, struct kern_ipc_perm *msq, struct msg_msg *msg, struct task_struct *target, long type, int mode) {
    union prov_elt *tprov, *cprov, *mprov;
    struct task_struct *current_task;

    current_task = (struct task_struct *)bpf_get_current_task_btf();
    if (!current_task)
        return 0;
    tprov = get_task_prov(current_task);
    if (!tprov)
      return 0;

    cprov = get_cred_prov_from_task(current_task);
    if (!cprov)
      return 0;

    mprov = get_msg_prov(msg);
    if (!mprov)
        return 0;

    uses(RL_RCV_MSG_Q, current_task, mprov, tprov, cprov, NULL, mode);
    return 0;
}

SEC("lsm/shm_alloc_security")
int BPF_PROG(shm_alloc_security, struct kern_ipc_perm *shp) {
    union prov_elt *tprov, *cprov, *sprov;
    struct task_struct *current_task;

    current_task = (struct task_struct *)bpf_get_current_task_btf();
    if (!current_task)
        return 0;
    tprov = get_task_prov(current_task);
    if (!tprov)
      return 0;

    cprov = get_cred_prov_from_task(current_task);
    if (!cprov)
      return 0;

    sprov = get_ipc_prov(shp);
    if (!sprov)
        return 0;

    generates(RL_SH_CREATE, current_task, cprov, tprov, sprov, NULL, 0);
    return 0;
}

SEC("lsm/shm_free_security")
int BPF_PROG(shm_free_security, struct kern_ipc_perm *shp) {
    union prov_elt *sprov;

    sprov = get_ipc_prov(shp);
    if (!sprov)
      return 0;

    record_terminate(RL_FREED, sprov);
    return 0;
}

#define	SHM_RDONLY	010000	/* read-only access */
SEC("lsm/shm_shmat")
int BPF_PROG(shm_shmat, struct kern_ipc_perm *shp, char *shmaddr, int shmflg) {
    union prov_elt *tprov, *cprov, *sprov;
    struct task_struct *current_task;

    current_task = (struct task_struct *)bpf_get_current_task_btf();
    if (!current_task)
      return 0;
    tprov = get_task_prov(current_task);
    if (!tprov)
      return 0;

    cprov = get_cred_prov_from_task(current_task);
    if (!cprov)
      return 0;

    sprov = get_ipc_prov(shp);
    if (!sprov)
        return 0;

    if (shmflg & SHM_RDONLY) {
      uses(RL_SH_ATTACH_READ, current_task, sprov, tprov, cprov, NULL, shmflg);
    } else {
      uses(RL_SH_ATTACH_READ, current_task, sprov, tprov, cprov, NULL, shmflg);
      generates(RL_SH_ATTACH_WRITE, current_task, cprov, tprov, sprov, NULL, shmflg);
    }
    return 0;
}

SEC("lsm/bprm_creds_for_exec")
int BPF_PROG(bprm_creds_for_exec, struct linux_binprm *bprm) {
    union prov_elt *cprov, *iprov;

    cprov = get_cred_prov(bprm->cred);
    if (!cprov)
      return 0;

    iprov = get_inode_prov(bprm->file->f_inode);
    if (!iprov)
      return 0;

    derives(RL_EXEC, iprov, cprov, NULL, 0);
    return 0;
}

SEC("lsm/bprm_committing_creds")
int BPF_PROG(bprm_committing_creds, struct linux_binprm *bprm) {
    union prov_elt *tprov, *cprov, *ncprov;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();


		current_task = (struct task_struct *)bpf_get_current_task_btf();
    if (!current_task)
      return 0;
    tprov = get_task_prov(current_task);
    if (!tprov)
      return 0;

    cprov = get_cred_prov_from_task(current_task);
    if (!cprov)
      return 0;

    ncprov = get_cred_prov(bprm->cred);
    if (!ncprov)
      return 0;

    generates(RL_EXEC_TASK, current_task, cprov, tprov, ncprov, NULL, 0);
    return 0;
}
