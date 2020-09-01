/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#ifndef __KERN_BPF_TASK_H
#define __KERN_BPF_TASK_H

#include "kern_bpf_node.h"

#define KB 1024
#define KB_MASK         (~(KB - 1))

//TODO: Need to further refactor this function.
static __always_inline void prov_update_task(struct task_struct *task,
                                             union prov_elt *prov) {

    bpf_probe_read(&prov->task_info.pid, sizeof(prov->task_info.pid), &task->pid);
    bpf_probe_read(&prov->task_info.vpid, sizeof(prov->task_info.vpid), &task->tgid);
    bpf_probe_read(&prov->task_info.utime, sizeof(prov->task_info.utime), &task->utime);
    bpf_probe_read(&prov->task_info.stime, sizeof(prov->task_info.stime), &task->stime);
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
#ifdef CONFIG_TASK_IO_ACCOUNTING
    bpf_probe_read(&prov->task_info.rbytes, sizeof(prov->task_info.rbytes), &task->ioac.read_bytes);
    prov->task_info.rbytes &= KB_MASK;
    bpf_probe_read(&prov->task_info.wbytes, sizeof(prov->task_info.wbytes), &task->ioac.write_bytes);
    prov->task_info.wbytes &= KB_MASK;
    bpf_probe_read(&prov->task_info.cancel_wbytes, sizeof(prov->task_info.cancel_wbytes), &task->ioac.cancelled_write_bytes);
    prov->task_info.cancel_wbytes &= KB_MASK;
#else
    bpf_probe_read(&prov->task_info.rbytes, sizeof(prov->task_info.rbytes), &task->ioac.rchar);
    prov->task_info.rbytes &= KB_MASK;
    bpf_probe_read(&prov->task_info.wbytes, sizeof(prov->task_info.wbytes), &task->ioac.wchar);
    prov->task_info.wbytes &= KB_MASK;
    prov->task_info.cancel_wbytes = 0;
#endif
}

static __always_inline union prov_elt* get_or_create_task_prov(
                                                struct task_struct *task,
                                                union prov_elt *new_prov) {
    uint64_t key = get_key(task);
    union prov_elt *old_prov = bpf_map_lookup_elem(&task_map, &key);
    // provenance already tracked
    if (old_prov) {
        prov_update_task(task, old_prov);
        return old_prov;
    } else { // new task
        __builtin_memset(new_prov, 0, sizeof(union prov_elt));
        prov_init_node(new_prov, ACT_TASK);
        prov_update_task(task, new_prov);
        bpf_map_update_elem(&task_map, &key, new_prov, BPF_NOEXIST);
        return new_prov;
    }
}
#endif
