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
