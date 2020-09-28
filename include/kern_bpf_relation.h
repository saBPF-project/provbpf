/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#ifndef __KERN_BPF_RELATION_H
#define __KERN_BPF_RELATION_H

/* Initialize common fields of a node's provenance */
static __always_inline void prov_init_relation(union long_prov_elt *prov,
                                                uint64_t type,
                                                const struct file *file,
					                            const uint64_t flags) {
    relation_identifier(prov).type=type;
    relation_identifier(prov).id = prov_next_id(RELATION_ID_INDEX);
    relation_identifier(prov).boot_id = prov_get_id(BOOT_ID_INDEX);
    relation_identifier(prov).machine_id = prov_get_id(MACHINE_ID_INDEX);
    if (file) {
		prov->relation_info.set = FILE_INFO_SET;
		prov->relation_info.offset = file->f_pos;
	}
    prov->relation_info.flags = flags;
}

static __always_inline void record_terminate(uint64_t type, union long_prov_elt *node) {
    union long_prov_elt *relation;
    int map_id = 0;
    relation = bpf_map_lookup_elem(&tmp_prov_map, &map_id);
    if (!relation) {
        return;
    }
    prov_init_relation(relation, type, NULL, 0);
    // set send node
    __builtin_memcpy(&(relation->relation_info.snd), &node_identifier(node), sizeof(union prov_identifier));
    record_provenance(node);
    // update node version
    node_identifier(node).version++;
    // set rcv node
    __builtin_memcpy(&(relation->relation_info.rcv), &node_identifier(node), sizeof(union prov_identifier));
    record_provenance(node);

    record_provenance(relation);
}

static __always_inline void record_relation(uint64_t type,
                                            union long_prov_elt *from,
                                            union long_prov_elt *to,
                                            const struct file *file,
                                            const uint64_t flags) {

    union long_prov_elt *prov_tmp;
    int map_id;
    prov_tmp = bpf_map_lookup_elem(&tmp_prov_map, &map_id);
    if (!prov_tmp) {
        return;
    }

    prov_init_relation(prov_tmp, type, file, flags);

    /*
        TODO handle versioning
        original logic:
        https://github.com/CamFlow/camflow-dev/blob/master/security/provenance/include/provenance_record.h#L52
    */

    // set send node
    __builtin_memcpy(&(prov_tmp->relation_info.snd), &node_identifier(from), sizeof(union prov_identifier));
    // set rcv node
    __builtin_memcpy(&(prov_tmp->relation_info.rcv), &node_identifier(to), sizeof(union prov_identifier));

    // record everything
    record_provenance(from);
    record_provenance(to);
    record_provenance(prov_tmp);
}

/*!
 * @brief Record "used" relation from entity provenance node to activity
 * provenance node, including its memory state.
 *
 * This function applies to only "used" relation between two provenance nodes.
 * Unless all nodes involved (entity, activity, activity_mem) are set not to be
 * tracked and prov_all is also turned off,
 * or unless the relation type is set not to be tracked,
 * relation will be captured.
 * At least two relations will possibly be captured:
 * 1. Whatever relation between entity and activity given by the argument
 * "type", and
 * 2. RL_PROC_WRITE relation between activity and activity_mem
 * If activity_mem has memory mapped files, a SH_WRITE relation may be captured
 * (see function definition of "current_update_shst").
 * @param type The type of relation (in the category of "used") between entity
 * and activity.
 * @param entity The entity provenance node.
 * @param activity The activity provenance node.
 * @param activity_mem The memory provenance node of the activity.
 * @param file Information related to LSM hooks.
 * @param flags Information related to LSM hooks.
 * @return 0 if no error occurred. Other error codes unknown.
 *
 */
static __always_inline void uses(const uint64_t type,
                                 struct task_struct *current,
                                 union long_prov_elt *entity,
                                 union long_prov_elt *activity,
                                 union long_prov_elt *activity_mem,
                                 const struct file *file,
                                 const uint64_t flags) {
    record_relation(type, entity, activity, file, flags);
    record_relation(RL_PROC_WRITE, activity, activity_mem, NULL, 0);
}

/*!
 * @brief Record "used" relation from entity provenance node to activity
 * provenance node. This function is a stripped-down version of "uses"
 * function.
 *
 * This function applies to only "used" relation between two provenance nodes.
 * @param type The type of relation (in the category of "used") between entity
 * and activity.
 * @param entity The entity provenance node.
 * @param activity The activity provenance node.
 * @param file Information related to LSM hooks.
 * @param flags Information related to LSM hooks.
 * @return 0 if no error occurred. Other error codes unknown.
 *
 */
static __always_inline void uses_two(uint64_t type,
                                     union long_prov_elt *entity,
                                     union long_prov_elt *activity,
                                     const struct file *file,
                                     const uint64_t flags) {

    record_relation(type, entity, activity, file, flags);
}

/*!
 * @brief Record "informed" relation from one activity provenance node to
 * another activity provenance node.
 *
 * This function applies to only "informed" relation between two activity
 * provenance nodes.
 * Unless both nodes involved (from, to) are set not to be tracked and prov_all
 * is also turned off,
 * or unless the relation type is set not to be tracked,
 * relation will be captured.
 * The relation is whatever relation between one activity node to another given
 * by the argument "type".
 * @param type The type of relation (in the category of "informed") between
 * two activities.
 * @param from The activity provenance node.
 * @param to The other activity provenance node.
 * @param file Information related to LSM hooks.
 * @param flags Information related to LSM hooks.
 * @return 0 if no error occurred. Other error codes unknown.
 *
 */
static __always_inline void informs(uint64_t type,
                                     union long_prov_elt *from,
                                     union long_prov_elt *to,
                                     const struct file *file,
                                     const uint64_t flags) {

    record_relation(type, from, to, file, flags);
}

/*!
 * @brief Record "derived" relation from one entity provenance node to another
 * entity provenance node.
 *
 * This function applies to only "derived" relation between two entity
 * provenance nodes.
 * Unless both nodes involved (from, to) are set not to be tracked and prov_all
 * is also turned off,
 * or unless the relation type is set not to be tracked,
 * relation will be captured.
 * The relation is whatever relation between one entity to another given by the
 * argument "type".
 * @param type The type of relation (in the category of "derived") between
 * two entities.
 * @param from The entity provenance node.
 * @param to The other entity provenance node.
 * @param file Information related to LSM hooks.
 * @param flags Information related to LSM hooks.
 * @return 0 if no error occurred. Other error codes unknown.
 *
 */
static __always_inline void derives(uint64_t type,
                                     union long_prov_elt *from,
                                     union long_prov_elt *to,
                                     const struct file *file,
                                     const uint64_t flags) {

    record_relation(type, from, to, file, flags);
}

// static __always_inline void current_update_shst(union long_prov_elt *cprov,
//                                                struct task_struct *current,
//                                                bool read) {
//     struct mm_struct *mm;
//     struct vm_area_struct *vma;
//     struct file *mmapf;
//     vm_flags_t flags;
//     union long_prov_elt *mmprov;
//
//     bpf_probe_read(&mm, sizeof(mm), &current->mm);
//     if (!mm)
//       return;
//     bpf_probe_read(&vma, sizeof(vma), &mm->mmap);
//     while (vma) {
//       bpf_probe_read(&mmapf, sizeof(mmapf), &vma->vm_file);
//       if (mmapf) {
//         bpf_probe_read(&flags, sizeof(flags), &vma->vm_flags);
//         struct inode *mmapf_inode;
//         bpf_probe_read(&mmapf_inode, sizeof(mmapf_inode), &mmapf->f_inode);
//         mmprov = get_or_create_inode_prov(mmapf_inode);
//         if (mmprov) {
//           if (vm_read_exec_mayshare(flags) && read) {
//             record_relation(RL_SH_READ, mmprov, cprov, mmapf, flags);
//           }
//           if (vm_write_mayshare(flags) && !read) {
//             record_relation(RL_SH_WRITE, cprov, mmprov, mmapf, flags);
//           }
//         }
//       }
//       vma = vma->vm_next;
//     }
// }

static __always_inline void generates(const uint64_t type,
                                      struct task_struct *current,
                                      union long_prov_elt *activity_mem,
                                      union long_prov_elt *activity,
                                      union long_prov_elt *entity,
                                      const struct file *file,
                                      const uint64_t flags) {

    // current_update_shst(activity_mem, current, true);
    record_relation(RL_PROC_READ, activity_mem, activity, NULL, 0);
    record_relation(type, activity, entity, file, flags);
}

#endif
