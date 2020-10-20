/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#ifndef __KERN_BPF_RELATION_H
#define __KERN_BPF_RELATION_H

/* Initialize common fields of a node's provenance */
static __always_inline void prov_init_relation(union prov_elt *prov,
                                                uint64_t type,
                                                const struct file *file,
					                                      const uint64_t flags)
{
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

/*!
 * @brief Write provenance relation to ring buffer.
 *
 * @param type The type of the relation (i.e., edge)
 * @param from The source node of the provenance edge
 * @param to The destination node of the provenance edge
 * @param file Information related to LSM hooks
 * @param flags Information related to LSM hooks
 *
 */
static __always_inline void __write_relation(const uint64_t type,
                                             void *from,
                                             bool from_is_long,
                                             void *to,
                                             bool to_is_long,
                                             const struct file *file,
                                             const uint64_t flags)
{
    union long_prov_elt *f, *t;
    f = from;
    t = to;
    union prov_elt prov_tmp;
    __builtin_memset(&prov_tmp, 0, sizeof(union prov_elt));

    prov_init_relation(&prov_tmp, type, file, flags);

    // set send node
    __builtin_memcpy(&(prov_tmp.relation_info.snd), &node_identifier(f), sizeof(union prov_identifier));
    // set rcv node
    __builtin_memcpy(&(prov_tmp.relation_info.rcv), &node_identifier(t), sizeof(union prov_identifier));

    record_provenance(from_is_long, from);
    record_provenance(to_is_long, to);
    // record relation provenance
    record_provenance(false, &prov_tmp);
}

static __always_inline void record_terminate(uint64_t type,
                                             void *node,
                                             bool node_is_long)
{
    union long_prov_elt *n = node;
    union prov_elt relation;
    __builtin_memset(&relation, 0, sizeof(union prov_elt));
    prov_init_relation(&relation, type, NULL, 0);
    // set send node
    __builtin_memcpy(&(relation.relation_info.snd), &node_identifier(n), sizeof(union prov_identifier));
    record_provenance(node_is_long, node);
    // update node version
    node_identifier(n).version++;
    // set rcv node
    __builtin_memcpy(&(relation.relation_info.rcv), &node_identifier(n), sizeof(union prov_identifier));
    record_provenance(node_is_long, node);

    record_provenance(false, &relation);
}

/*!
 * @brief This function updates the version of a provenance node.
 *
 * Versioning is used to avoid cycles in a provenance graph.
 * Given a provenance node, unless a certain criteria are met, the node should
 * be versioned to avoid cycles.
 * "old_prov" holds the older version of the node while "prov" is updated to
 * the newer version.
 * "prov" and "old_prov" have the same information except the version number.
 * Once the node with a new version is created, a relation between the old and
 * the new version should be estabilished.
 * The relation is either "RL_VERSION_TASK" or "RL_VERSION" depending on the
 * type of the nodes (note that they should be of the same type).
 * If the nodes are of type AC_TASK, then the relation should be
 * "RL_VERSION_TASK"; otherwise it is "RL_VERSION".
 * The new node is not recorded (therefore "recorded" flag is unset) until we
 * record it in the "__write_relation" function.
 * The new node is not saved for persistance in this function. So we clear the
 * saved bit inherited from the older version node.
 * The criteria that should be met to not update the version are:
 * 1. If nodes are set to be compressed and do not have outgoing edges, or
 * 2. If the argument "type" is a relation whose destination node's version
 * should not be updated becasue the "type" itself either is a VERSION type or
 * a NAMED type.
 * @param type The type of the relation.
 * @param prov The pointer to the provenance node whose version may need to be
 * updated.
 *
 */
static __always_inline void update_version(const uint64_t type,
                                          void *prov,
                                          bool prov_is_long)
{
    union prov_elt old_prov;

    __builtin_memset(&old_prov, 0, sizeof(union prov_elt));
    union long_prov_elt *p = prov;
    __builtin_memcpy(&old_prov, p, sizeof(union prov_elt));

    // Update the version of prov to the newer version
    node_identifier(p).version++;
    clear_recorded(p);

    // Record the version relation between two versions of the same identity.
    if (node_identifier(p).type == ACT_TASK) {
        __write_relation(RL_VERSION_TASK, &old_prov, prov_is_long, prov, prov_is_long, NULL, 0);
    } else {
        __write_relation(RL_VERSION, &old_prov, prov_is_long, prov, prov_is_long, NULL, 0);
    }
    // Newer version now has no outgoing edge
    clear_has_outgoing(p);
    // For inode provenance persistance
    clear_saved(p);
}

static __always_inline void record_relation(uint64_t type,
                                            void *from,
                                            bool from_is_long,
                                            void *to,
                                            bool to_is_long,
                                            const struct file *file,
                                            const uint64_t flags)
{
    // Update node version
    update_version(type, to, to_is_long);

    // Write relation provenance to ring buffer
    __write_relation(type, from, from_is_long, to, to_is_long, file, flags);
}

/*!
 * @brief Record shared mmap relations of a process.
 *
 * The function goes through all the mmapped files of the "current" process,
 * and for every shared mmaped file,
 * if the mmapped file has provenance entry,
 * record provenance relation between the mmaped file and the current process
 * based on the permission flags and the action (read, exec, or write).
 * If read/exec, record provenance relation RL_SH_READ by calling
 * "record_relation" function.
 * If write, record provenance relation RL_SH_WRITE by calling "record_relation"
 * function.
 * @param cprov The cred provenance entry pointer of the current process.
 * @param read Whether the operation is read or not.
 * @return 0 if no error occurred or "mm" is NULL; Other error codes inherited
 * from record_relation function or unknown.
 *
 */
// static __always_inline void current_update_shst(union prov_elt *cprov,
//                                                struct task_struct *current_task,
// 					                                     bool read)
// {
//     struct mm_struct *mm;
//     bpf_probe_read(&mm, sizeof(mm), &current_task->mm);
//     struct vm_area_struct *vma;
//     struct file *mmapf;
//
//     if (!mm)
//         return;
//     bpf_probe_read(&vma, sizeof(vma), &mm->mmap);
//     unsigned long vm_start, vm_end;
//     bpf_probe_read(&vm_start, sizeof(vm_start), &vma->vm_start);
//     bpf_probe_read(&vm_end, sizeof(vm_end), &vma->vm_end);
//
//     unsigned long length = (vm_end - vm_start) / sizeof(struct vm_area_struct);
//     struct vm_area_struct *vma_next;
//
//     while (vma) {
//       bpf_probe_read(&vma_next, sizeof(vma_next), &vma->vm_next);
//       // vma_next = vma->vm_next;
//       bpf_probe_read(&vma, sizeof(vma), &vma_next);
//     }
// }


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
                                 void *entity,
                                 bool entity_is_long,
                                 void *activity,
                                 bool activity_is_long,
                                 void *activity_mem,
                                 bool activity_mem_is_long,
                                 const struct file *file,
                                 const uint64_t flags) {
    record_relation(type, entity, entity_is_long, activity, activity_is_long, file, flags);
    record_relation(RL_PROC_WRITE, activity, activity_is_long, activity_mem, activity_mem_is_long, NULL, 0);
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
 *
 */
static __always_inline void uses_two(uint64_t type,
                                     void *entity,
                                     bool entity_is_long,
                                     void *activity,
                                     bool activity_is_long,
                                     const struct file *file,
                                     const uint64_t flags) {

    record_relation(type, entity, entity_is_long, activity, activity_is_long, file, flags);
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
                                     void *from,
                                     bool from_is_long,
                                     void *to,
                                     bool to_is_long,
                                     const struct file *file,
                                     const uint64_t flags) {

    record_relation(type, from, from_is_long, to, to_is_long, file, flags);
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
                                     void *from,
                                     bool from_is_long,
                                     void *to,
                                     bool to_is_long,
                                     const struct file *file,
                                     const uint64_t flags) {

    record_relation(type, from, from_is_long, to, to_is_long, file, flags);
}

/*!
 * @brief Record "generated" relation from activity provenance node (including
 * its memory state) to entity provenance node.
 *
 * This function applies to only "generated" relation between two provenance
 * nodes.
 * Unless all nodes involved (entity, activity, activity_mem) are set not to be
 * tracked and prov_all is also turned off,
 * or unless the relation type is set not to be tracked,
 * relation will be captured.
 * At least two relations will possibly be captured:
 * 1. RL_PROC_READ relation between activity_mem and activity
 * 1. Whatever relation between activity and entity given by the argument
 * "type".
 * @param type The type of relation (in the category of "generated") between
 * activity and entity.
 * @param activity_mem The memory provenance node of the activity.
 * @param activity The activity provenance node.
 * @param entity The entity provenance node.
 * @param file Information related to LSM hooks.
 * @param flags Information related to LSM hooks.
 *
 */
static __always_inline void generates(const uint64_t type,
                                      struct task_struct *current,
                                      void *activity_mem,
                                      bool activity_mem_is_long,
                                      void *activity,
                                      bool activity_is_long,
                                      void *entity,
                                      bool entity_is_long,
                                      const struct file *file,
                                      const uint64_t flags)
{
    record_relation(RL_PROC_READ, activity_mem, activity_mem_is_long, activity, activity_is_long, NULL, 0);
    record_relation(type, activity, activity_is_long, entity, entity_is_long, file, flags);
}

/*!
 * @brief This function records relations related to setting extended file
 * attributes.
 *
 * xattr is a long provenance entry and is transient (i.e., freed after
 * recorded).
 * Unless certain criteria are met, several relations are recorded when a
 * process attempts to write xattr of a file:
 * 1. Record a RL_PROC_READ relation between a task process and its cred.
 * Information flows from cred to the task process, and
 * 2. Record a given type @type of relation between the process and xattr
 * provenance entry. Information flows from the task to the xattr, and
 * 3-1. If the given type is RL_SETXATTR, then record a RL_SETXATTR_INODE
 * relation between xattr and the file inode. Information flows from xattr
 * to inode;
 * 3-2. otherwise (the only other case is that the given type is
 * RL_RMVXATTR_INODE), record a RL_RMVXATTR_INODE relation between xattr and the
 * file inode. Information flows from xattr to inode.
 * The criteria to be met so as not to record the relations are:
 * 1. If any of the cred, task, and inode provenance are not tracked and if the
 * capture all is not set, or
 * 2. If the relation @type should not be recorded, or
 * 3. Failure occurred.
 * xattr name and value pair is recorded in the long provenance entry.
 * @param type The type of relation to be recorded.
 * @param iprov The inode provenance entry.
 * @param tprov The task provenance entry.
 * @param cprov The cred provenance entry.
 * @param name The name of the extended attribute.
 * @param value The value of that attribute.
 * @param size The size of the value.
 * @param flags Flags passed by LSM hooks.
 * @return 0 if no error occurred; -ENOMEM if no memory can be allocated from
 * long provenance cache to create a new long provenance entry. Other error
 * codes from "record_relation" function or unknown.
 *
 */
static __always_inline int record_write_xattr(uint64_t type,
                              					       void *iprov,
                              					       void *tprov,
                              					       void *cprov,
                              					       const char *name,
                              					       const void *value,
                              					       size_t size,
                              					       const uint64_t flags)
{
    int map_id = 0;
    union long_prov_elt *ptr_prov_xattr = bpf_map_lookup_elem(&tmp_prov_map, &map_id);
    if (!ptr_prov_xattr) {
      return 0;
    }
    prov_init_node((union prov_elt *)ptr_prov_xattr, ENT_XATTR);

    __builtin_memcpy(&(ptr_prov_xattr->xattr_info.name), &name, PROV_XATTR_NAME_SIZE);
    ptr_prov_xattr->xattr_info.name[PROV_XATTR_NAME_SIZE - 1] = '\0';

    ptr_prov_xattr->xattr_info.size = (size < PROV_XATTR_VALUE_SIZE) ? size : PROV_XATTR_VALUE_SIZE;

    record_relation(RL_PROC_READ, cprov, false, tprov, false, NULL, 0);
    __write_relation(type, tprov, false, ptr_prov_xattr, true, NULL, flags);

    if (type == RL_SETXATTR) {
      record_relation(RL_SETXATTR_INODE, ptr_prov_xattr, true, iprov, false, NULL, flags);
    } else {
      record_relation(RL_RMVXATTR_INODE, ptr_prov_xattr, true, iprov, false, NULL, flags);
    }

    return 0;
}

/*!
 * @brief This function records relations related to reading extended file
 * attributes.
 *
 * xattr is a long provenance entry and is transient (i.e., freed after
 * recorded).
 * Unless certain criteria are met, several relations are recorded when a
 * process attempts to read xattr of a file:
 * 1. Record a RL_GETXATTR_INODE relation between inode and xattr. Information
 * flows from inode to xattr (to get xattr of an inode).
 * 2. Record a RL_GETXATTR relation between xattr and task process. Information
 * flows from xattr to the task (task reads the xattr).
 * 3. Record a RL_PROC_WRITE relation between task and its cred. Information
 * flows from task to its cred.
 * The criteria to be met so as not to record the relations are:
 * 1. If any of the cred, task, and inode provenance are not tracked and if the
 * capture all is not set, or
 * 2. If the relation RL_GETXATTR should not be recorded, or
 * 3. Failure occurred.
 * @param cprov The cred provenance entry.
 * @param tprov The task provenance entry.
 * @param name The name of the extended attribute.
 * @return 0 if no error occurred; -ENOMEM if no memory can be allocated
 * from long provenance cache to create a new long provenance entry. Other error
 * codes from "record_relation" function or unknown.
 *
 */
static __always_inline void record_read_xattr(void *cprov,
                                              void *tprov,
                                              void *iprov,
                                              const char *name)
{
    int map_id = 0;
    union long_prov_elt *xattr = bpf_map_lookup_elem(&tmp_prov_map, &map_id);
    if (!xattr)
      return;
    prov_init_node((union prov_elt *)xattr, ENT_XATTR);

    __builtin_memcpy(&(xattr->xattr_info.name), &name, PROV_XATTR_NAME_SIZE);
    xattr->xattr_info.name[PROV_XATTR_NAME_SIZE - 1] = '\0';

    __write_relation(RL_GETXATTR_INODE, iprov, false, xattr, true, NULL, 0);
    record_relation(RL_GETXATTR, xattr, true, tprov, false, NULL, 0);
    record_relation(RL_PROC_WRITE, tprov, false, cprov, false, NULL, 0);
}

#endif
