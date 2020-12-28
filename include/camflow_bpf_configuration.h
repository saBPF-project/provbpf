/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#ifndef __CAMFLOW_BPF_CONFIGURATION_H
#define __CAMFLOW_BPF_CONFIGURATION_H

#include <limits.h>

typedef struct{
    char log_path[PATH_MAX];
} configuration;

void read_config(void);

#endif
