/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#ifndef __CAMFLOW_BPF_ID_H
#define __CAMFLOW_BPF_ID_H

struct id_elem {
    uint64_t id;
};

#define RELATION_ID_INDEX 0
#define NODE_ID_INDEX 1
#define BOOT_ID_INDEX 2
#define MACHINE_ID_INDEX 3

#define ID_MAX_ENTRY 4

#define CAMFLOW_MACHINE_ID_FILE "/etc/camflow-machine_id"
#define CAMFLOW_BOOT_ID_FILE "/etc/camflow-boot_id"

// implemented for user space
uint32_t get_boot_id(void);
uint32_t get_machine_id(void);

#endif
