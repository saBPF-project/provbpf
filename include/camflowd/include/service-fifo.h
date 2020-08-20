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
#ifndef __SERVICE_FIFO_H
#define __SERVICE_FIFO_H
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "service-config.h"

static int __fifo_fd=0;

static inline void _init_fifo ( void ) {
  if (mkfifo(__service_config.fifo, 0666) < 0) {
    syslog(LOG_ERR, "Failed make FIFO %s\n", __service_config.fifo);
    exit(-1);
  }

  __fifo_fd = open(__service_config.fifo, O_WRONLY);
  if(__fifo_fd < 0) {
    syslog(LOG_ERR, "Failed opening named FIFO\n");
    exit(-1);
  }

  provenance_opaque_file(__service_config.fifo, true);
}

static void write_fifo_json(char* json) {
  write(__fifo_fd, json, strlen(json)+1);
}
#endif
