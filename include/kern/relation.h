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
#ifndef __KERN_BPF_RELATION_H
#define __KERN_BPF_RELATION_H

#define MAX_VMA 16

/* Initialize common fields of a node's provenance */
static __always_inline void prov_init_relation(union prov_elt *prov,
                                                uint64_t type,
                                                const struct file *file,
					                                      const uint64_t flags)
{
    loff_t offset;
    relation_identifier(prov).type=type;
    relation_identifier(prov).id = prov_next_id(RELATION_ID_INDEX);
    relation_identifier(prov).boot_id = prov_get_id(BOOT_ID_INDEX);
    relation_identifier(prov).machine_id = prov_get_id(MACHINE_ID_INDEX);
    if (file) {
		prov->relation_info.set = FILE_INFO_SET;
    bpf_probe_read(&offset, sizeof(offset), &file->f_pos);
		prov->relation_info.offset = offset;
	}
    prov->relation_info.flags = flags;
}

/*!
 * @brief Whether a provenance relation between two nodes should be recorded
 * based on the user-defined filter.
 *
 * If either the relation type or at least one of the two end nodes are filtered
 * out (i.e., not to be recorded as defined by the user),
 * Then this function will return false.
 * Otherwise, the relation should be recorded and thus the function will return
 * true.
 * @param type The type of the relation
 * @param from The provenance node entry of the source node.
 * @param to The provenance node entry of the destination node.
 * @return True if the relation of type 'type' should be recorded; False if
 * otherwise.
 *
 */
static __always_inline bool should_record_relation(const uint64_t type,
						   union prov_elt *from,
						   union prov_elt *to)
{
	if (filter_node(from) || filter_node(to))
		return false;
	return true;
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
    int map_id = RELATION_PERCPU_TMP;
    union prov_elt *prov_tmp = bpf_map_lookup_elem(&tmp_prov_elt_map, &map_id);

    if (!prov_tmp)
        return;

    prov_init_relation(prov_tmp, type, file, flags);

    // set send node
    __builtin_memcpy(&(prov_tmp->relation_info.snd), &node_identifier(f), sizeof(union prov_identifier));
    // set rcv node
    __builtin_memcpy(&(prov_tmp->relation_info.rcv), &node_identifier(t), sizeof(union prov_identifier));

    record_provenance(from_is_long, from);
    record_provenance(to_is_long, to);
    // record relation provenance
    record_provenance(false, prov_tmp);
}

static __always_inline void record_terminate(uint64_t type,
                                             void *node)
{
    union long_prov_elt *n = node;
    union prov_elt relation;
    if (filter_node(n))
      return;

    __builtin_memset(&relation, 0, sizeof(union prov_elt));
    prov_init_relation(&relation, type, NULL, 0);
    // set send node
    __builtin_memcpy(&(relation.relation_info.snd), &node_identifier(n), sizeof(union prov_identifier));
    record_provenance(false, node);
    // update node version
    node_identifier(n).version++;
    // set rcv node
    __builtin_memcpy(&(relation.relation_info.rcv), &node_identifier(n), sizeof(union prov_identifier));
    record_provenance(false, node);

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

    union prov_elt *p = prov;
    __builtin_memset(&old_prov, 0, sizeof(union prov_elt));
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

static __always_inline void update_version_long(const uint64_t type,
                                          void *prov,
                                          bool prov_is_long)
{
    int map_id = 3;
    union long_prov_elt *old_prov = bpf_map_lookup_elem(&tmp_prov_map, &map_id);
    if (!old_prov)
        return;

    union long_prov_elt *p = prov;
    bpf_map_update_elem(&tmp_prov_map, &map_id, p, BPF_NOEXIST);
    // __builtin_memcpy(old_prov, p, sizeof(union prov_elt));

    // Update the version of prov to the newer version
    node_identifier(p).version++;
    clear_recorded(p);

    // Record the version relation between two versions of the same identity.
    if (node_identifier(p).type == ACT_TASK) {
        __write_relation(RL_VERSION_TASK, old_prov, prov_is_long, prov, prov_is_long, NULL, 0);
    } else {
        __write_relation(RL_VERSION, old_prov, prov_is_long, prov, prov_is_long, NULL, 0);
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
static __always_inline void current_update_shst(union prov_elt *cprov,
                                               struct task_struct *current_task,
					                                     bool read)
{
    struct mm_struct *mm;
    bpf_probe_read(&mm, sizeof(mm), &current_task->mm);
    struct vm_area_struct *vma;
    struct file *mmapf;
    vm_flags_t flags;
    union prov_elt *mmprov;
    struct inode *mmapf_inode;

    if (!mm)
        return;
    bpf_probe_read(&vma, sizeof(vma), &mm->mmap);

    for (int i = 0; i < MAX_VMA; i++) {
        // If this is the last mmaped file, break
        if (!vma)
            return;
        // Perform operations of vma
        bpf_probe_read(&mmapf, sizeof(mmapf), &vma->vm_file);
        if (!mmapf)
          return;
        bpf_probe_read(&flags, sizeof(flags), &vma->vm_flags);

        bpf_probe_read(&mmapf_inode, sizeof(mmapf_inode), &mmapf->f_inode);
        mmprov = get_or_create_inode_prov(mmapf_inode);
        if (mmprov) {
            if (vm_read_exec_mayshare(flags) && read) {
              record_relation(RL_SH_READ, mmprov, false, cprov, false, mmapf, flags);
            }

            if (vm_write_mayshare(flags) && !read) {
              record_relation(RL_SH_WRITE, cprov, false, mmprov, false, mmapf, flags);
            }
        }
        // Get next mmaped file
        bpf_probe_read(&vma, sizeof(vma), &vma->vm_next);
    }
    return;
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
                                 void *entity,
                                 void *activity,
                                 void *activity_mem,
                                 const struct file *file,
                                 const uint64_t flags) {

    if (!should_record_relation(type, entity, activity)) {
      return;
    }
    record_relation(type, entity, false, activity, false, file, flags);
    record_relation(RL_PROC_WRITE, activity, false, activity_mem, false, NULL, 0);
    current_update_shst(activity_mem, current, false);
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

    if (!should_record_relation(type, entity, activity)) {
      return;
    }
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
                                     void *to,
                                     const struct file *file,
                                     const uint64_t flags) {

    if (!should_record_relation(type, from, to)) {
      return;
    }
    record_relation(type, from, false, to, false, file, flags);
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
                                     void *to,
                                     const struct file *file,
                                     const uint64_t flags) {

    if (!should_record_relation(type, from, to)) {
      return;
    }
    record_relation(type, from, false, to, false, file, flags);
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
                                      void *activity,
                                      void *entity,
                                      const struct file *file,
                                      const uint64_t flags)
{
    if (!should_record_relation(type, activity, entity)) {
      return;
    }
    current_update_shst(activity_mem, current, true);
    record_relation(RL_PROC_READ, activity_mem, false, activity, false, NULL, 0);
    record_relation(type, activity, false, entity, false, file, flags);
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
    if (!should_record_relation(type, cprov, iprov)) {
      return 0;
    }

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
    update_version_long(type, ptr_prov_xattr, true);
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
    if (!should_record_relation(RL_GETXATTR, iprov, cprov)) {
      return;
    }

    int map_id = 0;
    union long_prov_elt *xattr = bpf_map_lookup_elem(&tmp_prov_map, &map_id);
    if (!xattr)
      return;
    prov_init_node((union prov_elt *)xattr, ENT_XATTR);

    __builtin_memcpy(&(xattr->xattr_info.name), &name, PROV_XATTR_NAME_SIZE);
    xattr->xattr_info.name[PROV_XATTR_NAME_SIZE - 1] = '\0';

    update_version_long(RL_GETXATTR_INODE, xattr, true);
    __write_relation(RL_GETXATTR_INODE, iprov, false, xattr, true, NULL, 0);
    record_relation(RL_GETXATTR, xattr, true, tprov, false, NULL, 0);
    record_relation(RL_PROC_WRITE, tprov, false, cprov, false, NULL, 0);
}

static __always_inline int record_influences_kernel(const uint64_t type,
                                                    union prov_elt *entity,
                                                    union prov_elt *activity,
                                                    const struct file *file)
{
    uint64_t key = 0;
    union long_prov_elt *ptr_prov_machine;
    ptr_prov_machine = bpf_map_lookup_elem(&prov_machine_map, &key);

    if (provenance_is_opaque(entity) || provenance_is_opaque(activity)) {
      return 0;
    }

    record_relation(RL_LOAD_FILE, entity, false, activity, false, file, 0);
    if (ptr_prov_machine) {
        update_version_long(type, ptr_prov_machine, true);
        __write_relation(type, activity, false, ptr_prov_machine, true, NULL, 0);
    }

    return 0;
}

static __always_inline int record_kernel_link(union prov_elt *ptr_prov) {
    uint64_t key = 0;
    union long_prov_elt *ptr_prov_machine;
    ptr_prov_machine = bpf_map_lookup_elem(&prov_machine_map, &key);

    if (!ptr_prov_machine) {
      return 0;
    }

    record_relation(RL_RAN_ON, ptr_prov_machine, true, ptr_prov, false, NULL, 0);
    return 0;
}

static __always_inline union prov_elt *get_task_provenance(struct task_struct *current_task, bool link) {
    union prov_elt *ptr_prov_current;

    ptr_prov_current = get_or_create_task_prov(current_task);
    if (!ptr_prov_current) {
      return NULL;
    }

    if (!provenance_is_opaque(ptr_prov_current) && link) {
      record_kernel_link(ptr_prov_current);
    }

    return ptr_prov_current;
}

#endif
