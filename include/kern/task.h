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
static __always_inline void prov_update_lsm_task(struct task_struct *task,
                                             	 union prov_elt *ptr_prov) {
    ptr_prov->task_info.pid = task->pid;
 	ptr_prov->task_info.vpid = task->tgid;
 	ptr_prov->task_info.utime = task->utime;
 	ptr_prov->task_info.stime = task->stime;
 	ptr_prov->task_info.vm = task->mm->total_vm;
 	// ptr_prov->task_info.rss = (task->mm->rss_stat.count[MM_FILEPAGES].counter +
 	//                           task->mm->rss_stat.count[MM_ANONPAGES].counter +
 	//                           task->mm->rss_stat.count[MM_SHMEMPAGES].counter) * IOC_PAGE_SIZE / KB;
 	ptr_prov->task_info.rss = 0; // TODO: eBPF Verifier error output: "Type 'atomic_long_t' is not a struct". Need to find a fix
 	ptr_prov->task_info.hw_vm = (task->mm->hiwater_vm > ptr_prov->task_info.vm) ? (task->mm->hiwater_vm * IOC_PAGE_SIZE / KB) : (ptr_prov->task_info.vm * IOC_PAGE_SIZE / KB);
 	ptr_prov->task_info.hw_rss = (task->mm->hiwater_rss > ptr_prov->task_info.rss) ? (task->mm->hiwater_rss * IOC_PAGE_SIZE / KB) : (ptr_prov->task_info.rss * IOC_PAGE_SIZE / KB);

}

/* Update fields in a task's provenance instrumented by eBPF */
static __always_inline void prov_update_bpf_task(struct task_struct *task,
											 	 pid_t pid, pid_t tgid,
                                             	 union prov_elt *ptr_prov) {

	ptr_prov->task_info.pid = pid;
    ptr_prov->task_info.vpid = tgid;
    bpf_probe_read(&ptr_prov->task_info.utime, sizeof(ptr_prov->task_info.utime), &task->utime);
    bpf_probe_read(&ptr_prov->task_info.stime, sizeof(ptr_prov->task_info.stime), &task->stime);
}

static __always_inline void prov_update_task(struct task_struct *task,
                                             union prov_elt *ptr_prov) {
	return;
}

/* Create a provenance entry for a task detected by an LSM
 * hook if it does not exist and insert it into the @task_map;
 * otherwise, updates its existing provenance.
 * Return either the new provenance entry pointer or the updated
 * provenance entry pointer. */
static __always_inline union prov_elt* get_or_create_lsm_task_prov(struct task_struct *task) {
	if (!task) {
		return NULL;
	}

	uint64_t key = get_key(task);
	union prov_elt *prov_on_map = bpf_map_lookup_elem(&task_map, &key);
	if (prov_on_map) {
		prov_update_lsm_task(task, prov_on_map);
	} else {
		union prov_elt init_prov = {};
		prov_init_node(&init_prov, ACT_TASK);
		prov_update_lsm_task(task, &init_prov);
		bpf_map_update_elem(&task_map, &key, &init_prov, BPF_NOEXIST);
		prov_on_map = bpf_map_lookup_elem(&task_map, &key);
	}
	return prov_on_map;
}

/* Create a provenance entry for a task instrumented by eBPF
 * if it does not exist and insert it into the @task_map;
 * otherwise, updates its existing provenance.
 * Return either the new provenance entry pointer or the updated
 * provenance entry pointer. */
static __always_inline union prov_elt* get_or_create_bpf_task_prov(struct task_struct *task, pid_t pid, pid_t tgid) {
	if (!task) {
		return NULL;
	}

	uint64_t key = get_key(task);
	union prov_elt *prov_on_map = bpf_map_lookup_elem(&task_map, &key);
	if (prov_on_map) {
		prov_update_bpf_task(task, pid, tgid, prov_on_map);
	} else {
		union prov_elt init_prov = {};
		prov_init_node(&init_prov, ACT_TASK);
		prov_update_bpf_task(task, pid, tgid, &init_prov);
		bpf_map_update_elem(&task_map, &key, &init_prov, BPF_NOEXIST);
		prov_on_map = bpf_map_lookup_elem(&task_map, &key);
	}
	return prov_on_map;
}

/* Create a provenance entry for a task if it does not exist
 * and insert it into the @task_map; otherwise, updates its
 * existing provenance. Return either the new provenance entry
 * pointer or the updated provenance entry pointer. */
 static __always_inline union prov_elt* get_or_create_task_prov(struct task_struct *task) {
    if (!task)
        return NULL;

    union prov_elt prov_tmp;
    uint64_t key = get_key(task);
    union prov_elt *prov_on_map = bpf_map_lookup_elem(&task_map, &key);
    // provenance is already tracked
    if (prov_on_map) {
        // update the task's provenance since it may have changed
        prov_update_task(task, prov_on_map);
    } else { // a new task
        __builtin_memset(&prov_tmp, 0, sizeof(union prov_elt));
        // int map_id = 0;
        // prov_tmp = bpf_map_lookup_elem(&tmp_prov_map, &map_id);
        // if (!prov_tmp) {
        //     return 0;
        // }
        prov_init_node(&prov_tmp, ACT_TASK);
        prov_update_task(task, &prov_tmp);
        // this function does not return the pointer that sucks
        bpf_map_update_elem(&task_map, &key, &prov_tmp, BPF_NOEXIST);
        prov_on_map = bpf_map_lookup_elem(&task_map, &key);
    }
    return prov_on_map;
 }
#endif
