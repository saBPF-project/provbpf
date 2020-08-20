/*
*
* Author: Thomas Pasquier <thomas.pasquier@bristol.ac.uk>
*
* Copyright (C) 2016-2017 Harvard University
* Copyright (C) 2017-2018 University of Cambridge
* Copyright (C) 2018-2019 University of Bristol
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2, as
* published by the Free Software Foundation.
*
*/
#ifndef __SERVICE_LOG_H
#define __SERVICE_LOG_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>

#include "service-config.h"

static int __log_fd=0;

static inline void _init_logs( void ){
  __log_fd = open(__service_config.log, O_CREAT|O_WRONLY, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
  if(__log_fd < 0){
    syslog(LOG_ERR, "Cannot open file\n");
    exit(-1);
  }
  lseek(__log_fd, 0, SEEK_END);
  syslog(LOG_INFO, "Starting audit service...\n");
  provenance_opaque_file(__service_config.log, true);
}

extern bool is_spade;
static inline void log_print(char* json){
  int len = strlen(json);
  int rc;

  while (len > 0) {
    rc = write(__log_fd, json, len);
    if(rc<0)
      exit(-1);
    json+=rc;
    len-=rc;
  }
  if (!is_spade)
    write(__log_fd, "\n", 1);
  fsync(__log_fd);
}
#endif
