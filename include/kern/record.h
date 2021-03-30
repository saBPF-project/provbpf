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

static __always_inline void write_to_rb(union prov_elt *prov) {
    if (!prov)
        return;
    bpf_ringbuf_output(&r_buf, prov, sizeof(union prov_elt), 0);
}

static __always_inline void write_node(union prov_elt *node){
    if(provenance_is_opaque(node))
        return;
    if (provenance_is_recorded(node))
		return;
    write_to_rb(node);
    set_prov_recorded(node);
}

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
        offset = file->f_pos;
		prov->relation_info.offset = offset;
	}
    prov->relation_info.flags = flags;
}

// record a graph relation
static __always_inline void __write_relation(const uint64_t type,
                                             union prov_elt *from,
                                             union prov_elt *to,
                                             const struct file *file,
                                             const uint64_t flags)
{
    int map_id = RELATION_PERCPU_TMP;
    union prov_elt *relation = bpf_map_lookup_elem(&tmp_prov_elt_map, &map_id);

    if (!relation)
        return;

    prov_init_relation(relation, type, file, flags);

    // set send node
    __builtin_memcpy(&(relation->relation_info.snd), &node_identifier(from), sizeof(union prov_identifier));
    // set rcv node
    __builtin_memcpy(&(relation->relation_info.rcv), &node_identifier(to), sizeof(union prov_identifier));

    write_node(from);
    write_node(to);
    // record relation provenance
    write_to_rb(relation);
}

static __always_inline bool filter_update_node(const uint64_t relation_type)
{
	if (relation_type == RL_VERSION_TASK)
		return true;
	if (relation_type == RL_VERSION)
		return true;
	if (relation_type == RL_NAMED)
		return true;
	return false;
}

static __always_inline void __update_version(const uint64_t type,
					       union prov_elt *prov)
{
    union prov_elt old_prov;

    // if there are no outgoing edge we do not need to update
    if (!provenance_has_outgoing(prov))
        return;
    // some type of relation should not generate updates
    if (filter_update_node(type))
		return;

    __builtin_memcpy(&old_prov, prov, sizeof(union prov_elt));
    // Update the version of prov to the newer version
    node_identifier(prov).version++;
    clear_prov_recorded(prov);

    // Record the version relation between two versions of the same identity.
    if (node_identifier(prov).type == ACT_TASK) {
        __write_relation(RL_VERSION_TASK, &old_prov, prov, NULL, 0);
    } else {
        __write_relation(RL_VERSION, &old_prov, prov, NULL, 0);
    }
    // Newer version now has no outgoing edge
    clear_has_outgoing(prov);
}

// record a graph relation
static __always_inline void __record_relation(const uint64_t type,
                                             union prov_elt *from,
                                             union prov_elt *to,
                                             const struct file *file,
                                             const uint64_t flags)
{
    // do not repeat redundant edges
	if (node_previous_id(to) == node_identifier(from).id && node_previous_type(to) == type)
		return;

	node_previous_id(to) = node_identifier(from).id;
	node_previous_type(to) = type;
    // we update the destination node
    __update_version(type, to);
    // the source has an outgoing edge
    set_has_outgoing(from);
    __write_relation(type, from, to, file, flags);
}

static __always_inline void record_terminate(const uint64_t type,
					   union prov_elt *prov)
{
    union prov_elt old_prov;

    __builtin_memcpy(&old_prov, prov, sizeof(union prov_elt));
    // Update the version of prov to the newer version
    node_identifier(prov).version++;
    clear_prov_recorded(prov);
    __write_relation(type, &old_prov, prov, NULL, 0);
}


static __always_inline void uses(const uint64_t type,
                                 struct task_struct *current,
                                 void *entity,
                                 void *activity,
                                 void *activity_mem,
                                 const struct file *file,
                                 const uint64_t flags) {
    __record_relation(type, entity, activity, file, flags);
    __record_relation(RL_PROC_WRITE, activity, activity_mem, NULL, 0);
    // update shared
}

static __always_inline void generates(const uint64_t type,
                                      struct task_struct *current,
                                      void *activity_mem,
                                      void *activity,
                                      void *entity,
                                      const struct file *file,
                                      const uint64_t flags)
{
    // update shared
    __record_relation(RL_PROC_READ, activity_mem, activity, NULL, 0);
    __record_relation(type, activity, entity, file, flags);
}

static __always_inline void derives(uint64_t type,
                                     void *from,
                                     void *to,
                                     const struct file *file,
                                     const uint64_t flags) {
    __record_relation(type, from, to, file, flags);
}

static __always_inline void informs(uint64_t type,
                                     void *from,
                                     void *to,
                                     const struct file *file,
                                     const uint64_t flags) {
    __record_relation(type, from, to, file, flags);
}

#endif
