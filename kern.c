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
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <linux/limits.h>

#include "kern/sockaddr.h"

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
#include "kern/iattr.h"
#include "kern/relation.h"
#include "kern/net.h"

char _license[] SEC("license") = "GPL";


SEC("lsm/file_permission")
int BPF_PROG(file_permission, struct file *file, int mask) {
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    union prov_elt *ptask =retrieve_task_prov(current_task);
    union prov_elt *pcred = retrieve_cred_prov(current_task);
    write_to_rb(ptask);
    write_to_rb(pcred);
    return 0;
}

SEC("lsm/task_alloc")
int BPF_PROG(task_alloc, struct task_struct *task, unsigned long clone_flags) {
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
    union prov_elt *ptask =retrieve_task_prov(current_task);
    union prov_elt *potask =retrieve_task_prov(task);
    union prov_elt *pcred = retrieve_cred_prov(current_task);
    write_to_rb(ptask);
    write_to_rb(potask);
    write_to_rb(pcred);
    return 0;
}
