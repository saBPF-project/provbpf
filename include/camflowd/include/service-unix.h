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
#ifndef __SERVICE_UNIX_H
#define __SERVICE_UNIX_H
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "service-config.h"

#define CLIENT_SOCKET "tmp/camflowd-client.socket"

static int __unix_fd=0;

static inline void _init_unix ( void ){
  struct sockaddr_un addr;

  __unix_fd = socket(PF_UNIX, SOCK_DGRAM, 0);
  if(__unix_fd < 0){
    syslog(LOG_ERR, "Cannot create unix socket\n");
    exit(-1);
  }

  memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, CLIENT_SOCKET);
	unlink(CLIENT_SOCKET);
  if (bind(__unix_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0){
    syslog(LOG_ERR, "Could not bind unix socket\n");
    exit(-1);
  }

  memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, __service_config.unix_address);
	if (connect(__unix_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    syslog(LOG_ERR, "Could not connect to unix socket %s\n", __service_config.unix_address);
    exit(-1);
	}

  syslog(LOG_INFO, "Starting audit service...\n");

  provenance_opaque_file(__service_config.unix_address, true);
  provenance_opaque_file(CLIENT_SOCKET, true);
}

static void send_json(char* json){
  if (send(__unix_fd, json, strlen(json)+1, 0) < 0){
    syslog(LOG_ERR, "Could not send to unix socket %s\n", __service_config.unix_address);
    exit(-1);
  }
}
#endif
