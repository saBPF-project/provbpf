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

/* Update fields in a task's provenance */
// TODO: further refactor this function.
static __always_inline void prov_update_task(struct task_struct *task,
                                             union prov_elt *prov) {

    bpf_probe_read(&prov->task_info.pid, sizeof(prov->task_info.pid), &task->pid);
    bpf_probe_read(&prov->task_info.vpid, sizeof(prov->task_info.vpid), &task->tgid);
    bpf_probe_read(&prov->task_info.utime, sizeof(prov->task_info.utime), &task->utime);
    bpf_probe_read(&prov->task_info.stime, sizeof(prov->task_info.stime), &task->stime);
    /*
    struct mm_struct *mm;
    bpf_probe_read(&mm, sizeof(mm), &task->mm);
    bpf_probe_read(&prov->task_info.vm, sizeof(prov->task_info.vm), &mm->total_vm);
    prov->task_info.vm = prov->task_info.vm * IOC_PAGE_SIZE / KB;
    struct mm_rss_stat rss_stat;
    bpf_probe_read(&rss_stat, sizeof(rss_stat), &mm->rss_stat);
    prov->task_info.rss = (rss_stat.count[MM_FILEPAGES].counter +
                           rss_stat.count[MM_ANONPAGES].counter +
                           rss_stat.count[MM_SHMEMPAGES].counter) * IOC_PAGE_SIZE / KB;
    uint64_t current_task_hw_vm, current_task_hw_rss;
    bpf_probe_read(&current_task_hw_vm, sizeof(current_task_hw_vm), &mm->hiwater_vm);
    prov->task_info.hw_vm = u64_max(current_task_hw_vm, prov->task_info.vm) * IOC_PAGE_SIZE / KB;
    bpf_probe_read(&current_task_hw_rss, sizeof(current_task_hw_rss), &mm->hiwater_rss);
    prov->task_info.hw_rss = u64_max(current_task_hw_rss, prov->task_info.rss) * IOC_PAGE_SIZE / KB;
    */
}

/* Create a provenance entry for a task if it does not exist
 * and insert it into the @task_storage_map; otherwise, updates its
 * existing provenance. Return either the new provenance entry
 * pointer or the updated provenance entry pointer. */
 static __always_inline union prov_elt* get_or_create_task_prov(struct task_struct *task) {
    if (!task)
        return NULL;

    union prov_elt prov_tmp;
    union prov_elt *prov_on_map = bpf_task_storage_get(&task_storage_map, task, 0, 0);
    // provenance is already tracked
    if (prov_on_map) {
        // update the task's provenance since it may have changed
        prov_update_task(task, prov_on_map);
    } else { // a new task
        // int map_id = 0;
        // prov_tmp = bpf_map_lookup_elem(&tmp_prov_map, &map_id);
        // if (!prov_tmp) {
        //     return 0;
        // }
        prov_init_node(&prov_tmp, ACT_TASK);
        prov_update_task(task, &prov_tmp);
        prov_on_map = bpf_task_storage_get(&task_storage_map, task, &prov_tmp, BPF_NOEXIST | BPF_LOCAL_STORAGE_GET_F_CREATE);
    }
    return prov_on_map;
 }
#endif
