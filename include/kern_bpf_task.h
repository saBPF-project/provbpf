/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#ifndef __KERN_BPF_TASK_H
#define __KERN_BPF_TASK_H

#include "kern_bpf_node.h"

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
                                             union long_prov_elt *prov) {

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

/* Create a provenance entry for a task if it does not exist
 * and insert it into the @task_map; otherwise, updates its
 * existing provenance. Return either the new provenance entry
 * pointer or the updated provenance entry pointer. */
static __always_inline union long_prov_elt* get_or_create_task_prov(struct task_struct *task) {
    union long_prov_elt *prov_tmp;
    uint64_t key = get_key(task);
    union long_prov_elt *prov_on_map = bpf_map_lookup_elem(&task_map, &key);
    // provenance is already tracked
    if (prov_on_map) {
        // update the task's provenance since it may have changed
        prov_update_task(task, prov_on_map);
    } else { // a new task
        // __builtin_memset(&prov_tmp, 0, sizeof(union prov_elt));
        int map_id = 0;
        prov_tmp = bpf_map_lookup_elem(&tmp_prov_map, &map_id);
        if (!prov_tmp) {
            return 0;
        }
        prov_init_node(prov_tmp, ACT_TASK);
        prov_update_task(task, prov_tmp);
        // this function does not return the pointer that sucks
        bpf_map_update_elem(&task_map, &key, prov_tmp, BPF_NOEXIST);
        prov_on_map = bpf_map_lookup_elem(&task_map, &key);
    }
    return prov_on_map;
}
#endif
