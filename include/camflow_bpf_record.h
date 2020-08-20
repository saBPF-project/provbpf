/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#ifndef __PROVENANCE_BPF_RECORD_H
#define __PROVENANCE_BPF_RECORD_H

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <inttypes.h>
#include <errno.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <netdb.h>
#include <pthread.h>
#include <time.h>
#include <math.h>
#include <fcntl.h>
#include <sys/utsname.h>

#include "linux/provenance.h"
#include "linux/provenance_types.h"
#include "libprovenance/include/provenance.h"
#include "libprovenance/include/provenanceutils.h"
#include "libprovenance/include/provenanceW3CJSON.h"

#include "camflowd/include/service-config.h"
#include "camflowd/include/service-log.h"
#include "camflowd/include/service-mqtt.h"
#include "camflowd/include/service-unix.h"
#include "camflowd/include/service-fifo.h"


void prov_init();
void prov_record(union prov_elt* msg);

#endif
