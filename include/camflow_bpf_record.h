/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#ifndef __CAMFLOW_BPF_RECORD_H
#define __CAMFLOW_BPF_RECORD_H

#include "linux/provenance.h"

void bpf_prov_record(union long_prov_elt* msg);
void prov_refresh_records(void);
void prov_init(void);
#endif
