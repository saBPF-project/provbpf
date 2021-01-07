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
#define _GNU_SOURCE
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <syslog.h>
#include <stdlib.h>
#include <provenance.h>
#include <provenanceW3CJSON.h>
#include <provenanceSPADEJSON.h>
#include <pthread.h>

#include "camflow_bpf_record.h"
#include "camflow_bpf_configuration.h"

static struct provenance_ops prov_ops;

extern configuration __config;

void init( void ){
  pid_t tid = gettid();
  syslog(LOG_INFO, "Init audit thread (%d)", (int) tid);
}

void log_error(char* error){
  syslog(LOG_ERR, "From library: %s", error);
}

struct provenance_ops null_ops = {
  .init=&init,
  .log_derived=NULL,
  .log_generated=NULL,
  .log_used=NULL,
  .log_informed=NULL,
  .log_influenced=NULL,
  .log_associated=NULL,
  .log_proc=NULL,
  .log_task=NULL,
  .log_inode=NULL,
  .log_str=NULL,
  .log_act_disc=NULL,
  .log_agt_disc=NULL,
  .log_ent_disc=NULL,
  .log_msg=NULL,
  .log_shm=NULL,
  .log_packet=NULL,
  .log_address=NULL,
  .log_file_name=NULL,
  .log_iattr=NULL,
  .log_xattr=NULL,
  .log_packet_content=NULL,
  .log_arg=NULL,
  .log_machine=NULL,
  .log_error=&log_error
};

void w3c_str(struct str_struct* data){
  append_entity(str_msg_to_json(data));
}

void w3c_derived(struct relation_struct* relation){
  append_derived(derived_to_json(relation));
}

void w3c_generated(struct relation_struct* relation){
  append_generated(generated_to_json(relation));
}

void w3c_used(struct relation_struct* relation){
  append_used(used_to_json(relation));
}

void w3c_informed(struct relation_struct* relation){
  append_informed(informed_to_json(relation));
}

void w3c_influenced(struct relation_struct* relation){
  append_influenced(influenced_to_json(relation));
}

void w3c_associated(struct relation_struct* relation){
  append_associated(associated_to_json(relation));
}

void w3c_proc(struct proc_prov_struct* proc){
  append_entity(proc_to_json(proc));
}

void w3c_task(struct task_prov_struct* task){
  append_activity(task_to_json(task));
}

void w3c_inode(struct inode_prov_struct* inode){
  append_entity(inode_to_json(inode));
}

void w3c_act_disc(struct disc_node_struct* node){
  append_activity(disc_to_json(node));
}

void w3c_agt_disc(struct disc_node_struct* node){
  append_agent(disc_to_json(node));
}

void w3c_ent_disc(struct disc_node_struct* node){
  append_entity(disc_to_json(node));
}

void w3c_msg(struct msg_msg_struct* msg){
  append_entity(msg_to_json(msg));
}

void w3c_shm(struct shm_struct* shm){
  append_entity(shm_to_json(shm));
}

void w3c_packet(struct pck_struct* pck){
  append_entity(packet_to_json(pck));
}

void w3c_address(struct address_struct* address){
  append_entity(addr_to_json(address));
}

void w3c_file_name(struct file_name_struct* f_name){
  append_entity(pathname_to_json(f_name));
}

void w3c_iattr(struct iattr_prov_struct* iattr){
  append_entity(iattr_to_json(iattr));
}


void w3c_xattr(struct xattr_prov_struct* xattr){
  append_entity(xattr_to_json(xattr));
}

void w3c_packet_content(struct pckcnt_struct* cnt){
  append_entity(pckcnt_to_json(cnt));
}

void w3c_arg(struct arg_struct* arg){
  append_entity(arg_to_json(arg));
}

void w3c_machine(struct machine_struct* machine){
  append_agent(machine_to_json(machine));
}

struct provenance_ops w3c_ops = {
  .init=&init,
  .log_derived=&w3c_derived,
  .log_generated=&w3c_generated,
  .log_used=&w3c_used,
  .log_informed=&w3c_informed,
  .log_influenced=&w3c_influenced,
  .log_associated=&w3c_associated,
  .log_proc=&w3c_proc,
  .log_task=&w3c_task,
  .log_inode=&w3c_inode,
  .log_str=&w3c_str,
  .log_act_disc=&w3c_act_disc,
  .log_agt_disc=&w3c_agt_disc,
  .log_ent_disc=&w3c_ent_disc,
  .log_msg=&w3c_msg,
  .log_shm=&w3c_shm,
  .log_packet=&w3c_packet,
  .log_address=&w3c_address,
  .log_file_name=&w3c_file_name,
  .log_iattr=&w3c_iattr,
  .log_xattr=&w3c_xattr,
  .log_packet_content=&w3c_packet_content,
  .log_arg=&w3c_arg,
  .log_machine=&w3c_machine,
  .log_error=&log_error
};

void spade_derived(struct relation_struct* relation){
  spade_json_append(derived_to_spade_json(relation));
}

void spade_generated(struct relation_struct* relation){
  spade_json_append(generated_to_spade_json(relation));
}

void spade_used(struct relation_struct* relation){
  spade_json_append(used_to_spade_json(relation));
}

void spade_informed(struct relation_struct* relation){
  spade_json_append(informed_to_spade_json(relation));
}

void spade_influenced(struct relation_struct* relation){
  spade_json_append(influenced_to_spade_json(relation));
}

void spade_associated(struct relation_struct* relation){
  spade_json_append(associated_to_spade_json(relation));
}

void spade_proc(struct proc_prov_struct* proc){
    spade_json_append(proc_to_spade_json(proc));
}

void spade_task(struct task_prov_struct* task){
  spade_json_append(task_to_spade_json(task));
}

void spade_inode(struct inode_prov_struct* inode){
  spade_json_append(inode_to_spade_json(inode));
}

void spade_act_disc(struct disc_node_struct* node){
  spade_json_append(disc_to_spade_json(node));
}

void spade_agt_disc(struct disc_node_struct* node){
  spade_json_append(disc_to_spade_json(node));
}

void spade_ent_disc(struct disc_node_struct* node){
  spade_json_append(disc_to_spade_json(node));
}

void spade_msg(struct msg_msg_struct* msg){
  spade_json_append(msg_to_spade_json(msg));
}

void spade_shm(struct shm_struct* shm){
  spade_json_append(shm_to_spade_json(shm));
}

void spade_packet(struct pck_struct* pck){
  spade_json_append(packet_to_spade_json(pck));
}

void spade_address(struct address_struct* address){
  spade_json_append(addr_to_spade_json(address));
}

void spade_file_name(struct file_name_struct* f_name){
  spade_json_append(pathname_to_spade_json(f_name));
}

void spade_iattr(struct iattr_prov_struct* iattr){
  spade_json_append(iattr_to_spade_json(iattr));
}


void spade_xattr(struct xattr_prov_struct* xattr){
  spade_json_append(xattr_to_spade_json(xattr));
}

void spade_packet_content(struct pckcnt_struct* cnt){
  spade_json_append(pckcnt_to_spade_json(cnt));
}

void spade_arg(struct arg_struct* arg){
  spade_json_append(arg_to_spade_json(arg));
}

void spade_machine(struct machine_struct* m){
  spade_json_append(machine_to_spade_json(m));
}

struct provenance_ops spade_ops = {
  .init=&init,
  .log_derived=&spade_derived,
  .log_generated=&spade_generated,
  .log_used=&spade_used,
  .log_informed=&spade_informed,
  .log_influenced=&spade_influenced,
  .log_associated=&spade_associated,
  .log_proc=&spade_proc,
  .log_task=&spade_task,
  .log_inode=&spade_inode,
  .log_str=NULL,
  .log_act_disc=&spade_act_disc,
  .log_agt_disc=&spade_agt_disc,
  .log_ent_disc=&spade_ent_disc,
  .log_msg=&spade_msg,
  .log_shm=&spade_shm,
  .log_packet=&spade_packet,
  .log_address=&spade_address,
  .log_file_name=&spade_file_name,
  .log_iattr=&spade_iattr,
  .log_xattr=&spade_xattr,
  .log_packet_content=&spade_packet_content,
  .log_arg=&spade_arg,
  .log_machine=&spade_machine,
  .log_error=&log_error
};

void relation_record(union long_prov_elt *msg){
  uint64_t type = prov_type(msg);

  if(prov_is_used(type)) {
    if (prov_ops.log_used!=NULL)
        prov_ops.log_used(&(msg->relation_info));
  } else if(prov_is_informed(type)) {
    if (prov_ops.log_informed!=NULL)
        prov_ops.log_informed(&(msg->relation_info));
  } else if(prov_is_generated(type)) {
    if (prov_ops.log_generated!=NULL)
        prov_ops.log_generated(&(msg->relation_info));
  } else if(prov_is_derived(type)) {
    if (prov_ops.log_derived!=NULL)
        prov_ops.log_derived(&(msg->relation_info));
  } else if(prov_is_influenced(type)) {
    if (prov_ops.log_influenced!=NULL)
        prov_ops.log_influenced(&(msg->relation_info));
  } else if(prov_is_associated(type)) {
    if (prov_ops.log_associated!=NULL)
        prov_ops.log_associated(&(msg->relation_info));
  } else
    syslog(LOG_ERR, "ProvBPF: unknown relation type %lu.", prov_type(msg));
}

void node_record(union prov_elt *msg){
  switch(prov_type(msg)){
    case ENT_PROC:
      if(prov_ops.log_proc!=NULL)
        prov_ops.log_proc(&(msg->proc_info));
      break;
    case ACT_TASK:
      if(prov_ops.log_task!=NULL)
        prov_ops.log_task(&(msg->task_info));
      break;
    case ENT_INODE_UNKNOWN:
    case ENT_INODE_LINK:
    case ENT_INODE_FILE:
    case ENT_INODE_DIRECTORY:
    case ENT_INODE_CHAR:
    case ENT_INODE_BLOCK:
    case ENT_INODE_PIPE:
    case ENT_INODE_SOCKET:
      if(prov_ops.log_inode!=NULL)
        prov_ops.log_inode(&(msg->inode_info));
      break;
    case ENT_MSG:
      if(prov_ops.log_msg!=NULL)
        prov_ops.log_msg(&(msg->msg_msg_info));
      break;
    case ENT_SHM:
      if(prov_ops.log_shm!=NULL)
        prov_ops.log_shm(&(msg->shm_info));
      break;
    case ENT_PACKET:
      if(prov_ops.log_packet!=NULL)
        prov_ops.log_packet(&(msg->pck_info));
      break;
    case ENT_IATTR:
      if(prov_ops.log_iattr!=NULL)
        prov_ops.log_iattr(&(msg->iattr_info));
      break;
    default:
      syslog(LOG_ERR, "ProvBPF: unknown node type %lu.", prov_type(msg));
      break;
  }
}

void long_prov_record(union long_prov_elt* msg){
  switch(prov_type(msg)){
    case ENT_STR:
      if(prov_ops.log_str!=NULL)
        prov_ops.log_str(&(msg->str_info));
      break;
    case ENT_PATH:
      if(prov_ops.log_file_name!=NULL)
        prov_ops.log_file_name(&(msg->file_name_info));
      break;
    case ENT_ADDR:
      if(prov_ops.log_address!=NULL)
        prov_ops.log_address(&(msg->address_info));
      break;
    case ENT_XATTR:
      if(prov_ops.log_xattr!=NULL)
        prov_ops.log_xattr(&(msg->xattr_info));
      break;
    case ENT_DISC:
      if(prov_ops.log_ent_disc!=NULL)
        prov_ops.log_ent_disc(&(msg->disc_node_info));
      break;
    case ACT_DISC:
      if(prov_ops.log_act_disc!=NULL)
        prov_ops.log_act_disc(&(msg->disc_node_info));
      break;
    case AGT_DISC:
      if(prov_ops.log_agt_disc!=NULL)
        prov_ops.log_agt_disc(&(msg->disc_node_info));
      break;
    case ENT_PCKCNT:
      if(prov_ops.log_packet_content!=NULL)
        prov_ops.log_packet_content(&(msg->pckcnt_info));
      break;
    case ENT_ARG:
    case ENT_ENV:
      if(prov_ops.log_arg!=NULL)
        prov_ops.log_arg(&(msg->arg_info));
      break;
    case AGT_MACHINE:
      if(prov_ops.log_machine!=NULL)
        prov_ops.log_machine(&(msg->machine_info));
      break;
    default:
      syslog(LOG_ERR, "ProvBPF: unknown node long type %lx.", prov_type(msg));
      break;
  }
}

static int __log_fd;
static pthread_mutex_t __file_lock;

static inline void log_to_file(char* json){
    int len = strlen(json);
    int rc;

    pthread_mutex_lock(&__file_lock);
    while (len > 0) {
        rc = write(__log_fd, json, len);
        if(rc<0)
            exit(-1);
        json+=rc;
        len-=rc;
    }
    rc = write(__log_fd, "\n", 1);
    if(rc<0)
        exit(-1);
    fsync(__log_fd);
    pthread_mutex_unlock(&__file_lock);
}

static inline void log_to_terminal(char* json){
    printf("%s\n", json);
}

void prov_init() {
    if (__config.output == CF_BPF_LOG) {
        /* setup log file */
        syslog(LOG_INFO, "ProvBPF: Log file %s.", __config.log_path);
        __log_fd = open(__config.log_path, O_CREAT|O_WRONLY, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
        if (__log_fd < 0) {
            syslog(LOG_ERR, "ProvBPF: Cannot open log file.");
            exit(-1);
        }
        lseek(__log_fd, 0, SEEK_SET);

        if (pthread_mutex_init(&__file_lock, NULL) != 0) {
            syslog(LOG_ERR, "ProvBPF: File mutex init failed.");
            exit(-1);
        }

        /* ready the recording hooks */
        if (__config.format == CF_BPF_W3C) {
            memcpy(&prov_ops, &w3c_ops, sizeof(struct provenance_ops));
            set_W3CJSON_callback(log_to_file);
        } else if (__config.format == CF_BPF_SPADE) {
            memcpy(&prov_ops, &spade_ops, sizeof(struct provenance_ops));
            set_SPADEJSON_callback(log_to_file);
        } else {
            syslog(LOG_ERR, "ProvBPF: Unknown format.");
            exit(-1);
        }
    } else if (__config.output == CF_BPF_TERMINAL) {
        /* ready the recording hooks */
        if (__config.format == CF_BPF_W3C) {
            memcpy(&prov_ops, &w3c_ops, sizeof(struct provenance_ops));
            set_W3CJSON_callback(log_to_terminal);
        } else if (__config.format == CF_BPF_SPADE) {
            memcpy(&prov_ops, &spade_ops, sizeof(struct provenance_ops));
            set_SPADEJSON_callback(log_to_terminal);
        } else {
            syslog(LOG_ERR, "ProvBPF: Unknown format.");
            exit(-1);
        }
    } else if (__config.output == CF_BPF_NULL) {
        /* ready the recording hooks */
        memcpy(&prov_ops, &null_ops, sizeof(struct provenance_ops));
    }  else {
        syslog(LOG_ERR, "ProvBPF: error initializing logging.");
        exit(-1);
    }
}

void bpf_prov_record(void *raw_msg){
    union long_prov_elt *msg = (union long_prov_elt*)raw_msg;
    if (prov_is_relation(msg)) {
      relation_record(msg);
    } else {
      if (prov_type_is_long(node_type(msg))) {
        long_prov_record(msg);
      } else {
        node_record((union prov_elt *)msg);
      }
    }
}

void prov_refresh_records(void) {
    sleep(1);
    if (__config.output == CF_BPF_NULL)
        return;
    if (__config.format == CF_BPF_W3C)
        flush_json();
    if (__config.format == CF_BPF_SPADE)
        flush_spade_json();
}
