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
#ifndef __CAMFLOW_BPF_RECORD_H
#define __CAMFLOW_BPF_RECORD_H

#include "shared/prov_struct.h"
#include "shared/policy.h"

struct provenance_ops{
  void (*init)(void);
  bool (*filter)(prov_entry_t* msg);
  void (*received_prov)(union prov_elt*);
  void (*received_long_prov)(union long_prov_elt*);
  /* relation callback */
  void (*log_derived)(struct relation_struct*);
  void (*log_generated)(struct relation_struct*);
  void (*log_used)(struct relation_struct*);
  void (*log_informed)(struct relation_struct*);
  void (*log_influenced)(struct relation_struct*);
  void (*log_associated)(struct relation_struct*);
  /* nodes callback */
  void (*log_proc)(struct proc_prov_struct*);
  void (*log_task)(struct task_prov_struct*);
  void (*log_inode)(struct inode_prov_struct*);
  void (*log_msg)(struct msg_msg_struct*);
  void (*log_shm)(struct shm_struct*);
  void (*log_packet)(struct pck_struct*);
  void (*log_address)(struct address_struct*);
  void (*log_file_name)(struct file_name_struct*);
  void (*log_iattr)(struct iattr_prov_struct*);
  void (*log_xattr)(struct xattr_prov_struct*);
  void (*log_packet_content)(struct pckcnt_struct*);
  void (*log_arg)(struct arg_struct*);
  void (*log_machine)(struct machine_struct*);
  /* callback for library errors */
  void (*log_error)(char*);
  /* is it filter only? for query framework */
  bool is_query;
};

void bpf_prov_record(union long_prov_elt* msg);
void prov_refresh_records(void);
void prov_record_init(void);
#endif
