/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#ifndef __CAMFLOW_BPF_CONFIGURATION_H
#define __CAMFLOW_BPF_CONFIGURATION_H

#include <limits.h>

enum output_type {
    CF_BPF_LOG,
    CF_BPF_TERMINAL,
    CF_BPF_NULL
};

typedef struct {
    char log_path[PATH_MAX];
    enum output_type output;
} configuration;



void read_config(void);

#endif
