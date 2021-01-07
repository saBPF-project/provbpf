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
#ifndef __KERN_BPF_CRED_H
#define __KERN_BPF_CRED_H

#include "kern_bpf_node.h"

// Update fields in a cred's provenance
static __always_inline void prov_update_cred(struct task_struct *current_task,
                                             union prov_elt *prov) {
    struct nsproxy *current_nsproxy;
    struct uts_namespace *uts_ns;
    struct ipc_namespace *ipc_ns;
    struct mnt_namespace *mnt_ns;
    struct pid_namespace *pid_ns;
    struct net *net_ns;
    struct cgroup_namespace *cgroup_ns;

    bpf_probe_read(&prov->proc_info.tgid, sizeof(prov->proc_info.tgid), &current_task->tgid);

    bpf_probe_read(&current_nsproxy, sizeof(current_nsproxy), &current_task->nsproxy);

    // UTS Namespace
    bpf_probe_read(&uts_ns, sizeof(uts_ns), &current_nsproxy->uts_ns);
    bpf_probe_read(&prov->proc_info.utsns, sizeof(prov->proc_info.utsns), &uts_ns->ns.inum);
    // IPC Namespace
    bpf_probe_read(&ipc_ns, sizeof(ipc_ns), &current_nsproxy->ipc_ns);
    bpf_probe_read(&prov->proc_info.ipcns, sizeof(prov->proc_info.ipcns), &ipc_ns->ns.inum);
    // Mount namespace
    bpf_probe_read(&mnt_ns, sizeof(mnt_ns), &current_nsproxy->mnt_ns);
    bpf_probe_read(&prov->proc_info.mntns, sizeof(prov->proc_info.mntns), &mnt_ns->ns.inum);
    // Network namespace
    bpf_probe_read(&net_ns, sizeof(net_ns), &current_nsproxy->net_ns);
    bpf_probe_read(&prov->proc_info.netns, sizeof(prov->proc_info.netns), &net_ns->ns.inum);
    // Cgroup namespace
    bpf_probe_read(&cgroup_ns, sizeof(cgroup_ns), &current_nsproxy->cgroup_ns);
    bpf_probe_read(&prov->proc_info.cgroupns, sizeof(prov->proc_info.cgroupns), &cgroup_ns->ns.inum);

    struct pid *current_pid;
    uint32_t current_pid_level;
    bpf_probe_read(&current_pid, sizeof(current_pid), &current_task->thread_pid);
    bpf_probe_read(&current_pid_level, sizeof(current_pid_level), &current_pid->level);
    // PID namespace
    bpf_probe_read(&pid_ns, sizeof(pid_ns), &current_pid->numbers[current_pid_level].ns);
    bpf_probe_read(&prov->proc_info.pidns, sizeof(prov->proc_info.pidns), &pid_ns->ns.inum);
}

/* Create a provenance entry for a cred if it does not exist
 * and insert it into the @cred_map; otherwise, updates its
 * existing provenance. Return either the new provenance entry
 * pointer or the updated provenance entry pointer. */
static __always_inline union prov_elt* get_or_create_cred_prov(const struct cred *cred, struct task_struct *current_task) {
    if (!cred) {
      return NULL;
    }

    union prov_elt prov_tmp;
    uint64_t key = get_key(cred);
    union prov_elt *prov_on_map = bpf_map_lookup_elem(&cred_map, &key);
    // provenance is already tracked
    if (prov_on_map) {
      // update the cred's provenance since it may have changed
      prov_update_cred(current_task, prov_on_map);
    } else {
      // a new cred
      __builtin_memset(&prov_tmp, 0, sizeof(union prov_elt));
      prov_init_node(&prov_tmp, ENT_PROC);
      prov_update_cred(current_task, &prov_tmp);
      bpf_map_update_elem(&cred_map, &key, &prov_tmp, BPF_NOEXIST);
      prov_on_map = bpf_map_lookup_elem(&cred_map, &key);
    }
    return prov_on_map;
}

#endif
