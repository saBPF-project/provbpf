/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#ifndef __CAMFLOW_BPF_RECORD_H
#define __CAMFLOW_BPF_RECORD_H

#include "linux/provenance.h"
#include "kern_bpf_policy.h"

void bpf_prov_record(void *raw_msg);
void prov_refresh_records(void);
void prov_init(void);
#endif
