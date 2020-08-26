/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#ifndef __PROVENANCE_BPF_ID_H
#define __PROVENANCE_BPF_ID_H

struct id_elem {
    uint64_t id;
};

#define RELATION_ID_INDEX 0
#define NODE_ID_INDEX 1
#define BOOT_ID_INDEX 2
#define MACHINE_ID_INDEX 3

#define ID_MAX_ENTRY 4

#endif
