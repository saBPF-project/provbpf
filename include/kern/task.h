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
#ifndef __KERN_BPF_TASK_H
#define __KERN_BPF_TASK_H

#include "kern/node.h"

#define KB 1024
#define KB_MASK         (~(KB - 1))

#define VM_NONE		0x00000000

#define VM_READ		0x00000001	/* currently active flags */
#define VM_WRITE	0x00000002
#define VM_EXEC		0x00000004
#define VM_SHARED	0x00000008

#define VM_MAYREAD	0x00000010	/* limits for mprotect() etc */
#define VM_MAYWRITE	0x00000020
#define VM_MAYEXEC	0x00000040
#define VM_MAYSHARE	0x00000080

#define vm_write(flags) ((flags & VM_WRITE) == VM_WRITE)
#define vm_read(flags) ((flags & VM_READ) == VM_READ)
#define vm_exec(flags) ((flags & VM_EXEC) == VM_EXEC)
#define vm_mayshare(flags) ((flags & (VM_SHARED | VM_MAYSHARE)) != 0)
#define vm_write_mayshare(flags) (vm_write(flags) && vm_mayshare(flags))
#define vm_read_exec_mayshare(flags) \
	((vm_read(flags) || vm_exec(flags)) && vm_mayshare(flags))

/* Update fields in a task's provenance detected by an LSM hook */
// TODO: further refactor this function.
static __always_inline void __update_task(const struct task_struct *task,
                                             union prov_elt *prov) {
    prov->task_info.tid = task->pid;
	prov->task_info.pid = task->tgid;
  	prov->task_info.utime = task->utime;
  	prov->task_info.stime = task->stime;
  	prov->task_info.vm = task->mm->total_vm;
  	// prov->task_info.rss = (task->mm->rss_stat.count[MM_FILEPAGES].counter +
  	//                           task->mm->rss_stat.count[MM_ANONPAGES].counter +
  	//                           task->mm->rss_stat.count[MM_SHMEMPAGES].counter) * IOC_PAGE_SIZE / KB;
  	prov->task_info.rss = 0; // TODO: eBPF Verifier error output: "Type 'atomic_long_t' is not a struct". Need to find a fix
  	prov->task_info.hw_vm = (task->mm->hiwater_vm > prov->task_info.vm) ? (task->mm->hiwater_vm * IOC_PAGE_SIZE / KB) : (prov->task_info.vm * IOC_PAGE_SIZE / KB);
  	prov->task_info.hw_rss = (task->mm->hiwater_rss > prov->task_info.rss) ? (task->mm->hiwater_rss * IOC_PAGE_SIZE / KB) : (prov->task_info.rss * IOC_PAGE_SIZE / KB);

	// namespaces
	prov->task_info.utsns = task->nsproxy->uts_ns->ns.inum;
	prov->task_info.ipcns = task->nsproxy->ipc_ns->ns.inum;
	prov->task_info.mntns = task->nsproxy->mnt_ns->ns.inum;
	prov->task_info.pidns = task->thread_pid->numbers[0].ns->ns.inum;
	prov->task_info.netns = task->nsproxy->net_ns->ns.inum;
	prov->task_info.cgroupns = task->nsproxy->cgroup_ns->ns.inum;

}

/* Create a provenance entry for a task if it does not exist
 * and insert it into the @task_storage_map; otherwise, updates its
 * existing provenance. Return either the new provenance entry
 * pointer or the updated provenance entry pointer. */
 static __always_inline union prov_elt* get_task_prov(struct task_struct * task) {
     struct provenance_holder *prov_holder;
     union prov_elt* prov;

    if(!task)
        return NULL;
    prov_holder = bpf_task_storage_get(&task_storage_map, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!prov_holder)
        return NULL;
    prov = &prov_holder->prov;
    if (!__set_initalized(prov))
        prov_init_node(prov, ACT_TASK);
    if (provenance_is_opaque(prov))
        return NULL;
    __update_task(task, prov);
    return prov;
 }
#endif
