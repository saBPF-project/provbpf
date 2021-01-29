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
#ifndef __CAMFLOW_BPF_CONFIGURATION_H
#define __CAMFLOW_BPF_CONFIGURATION_H

#include <limits.h>

enum output_type {
    CF_BPF_LOG,
    CF_BPF_TERMINAL,
    CF_BPF_NULL
};

enum format_type {
    CF_BPF_W3C,
    CF_BPF_SPADE
};

typedef struct {
    char log_path[PATH_MAX];
    enum output_type output;
    enum format_type format;
} configuration;



void read_config(void);

#endif
