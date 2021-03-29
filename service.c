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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <bpf/bpf.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <signal.h>
#include <errno.h>

#include "shared/prov_struct.h"
#include "shared/id.h"
#include "shared/prov_types.h"

#include "usr/provbpf.skel.h"
#include "usr/record.h"
#include "usr/configuration.h"

static struct provbpf *skel = NULL;

/* Callback function called whenever a new ring
 * buffer entry is polled from the buffer. */
static int buf_process_entry(void *ctx, void *data, size_t len) {
    /* Every entry from the ring buffer should
     * be of type union long_prov_elt.
     */

    union long_prov_elt *prov = (union long_prov_elt*)data;

    /* Userspace processing the provenance record. */
    bpf_prov_record(prov);

    return 0;
}

static void set_id(struct provbpf *skel, uint32_t index, uint64_t value) {
    int map_fd;
    struct id_elem id;
    map_fd = bpf_object__find_map_fd_by_name(skel->obj, "ids_map");
    id.id = value;
    bpf_map_update_elem(map_fd, &index, &id, BPF_ANY);
}

static uint64_t prov_next_id(uint32_t key, struct provbpf *skel)	{
    int map_fd = bpf_object__find_map_fd_by_name(skel->obj, "ids_map");
    if (map_fd < 0) {
      syslog(LOG_ERR, "ProvBPF: Failed loading ids_map (%d).", map_fd);
      return 0;
    }

    struct id_elem val;
    int res = bpf_map_lookup_elem(map_fd, &key, &val);
    if (res == -1)
        return 0;
    __sync_fetch_and_add(&val.id, 1);
    // TODO: eBPF seems to have issue with __sync_fetch_and_add
    // TODO: we cannot obtain the return value of the function.
    // TODO: Perhaps we need a lock to avoid race conditions.
    return val.id;
}

/* djb2 hash implementation by Dan Bernstein */
static uint64_t djb2_hash(const char *str)
{
	uint64_t hash = 5381;
	int c = *str;

	while (c) {
		hash = ((hash << 5) + hash) + c;
		c = *++str;
	}
	return hash;
}

static void sig_handler(int sig) {
    if (sig == SIGTERM) {
        syslog(LOG_INFO, "ProvBPF: Received termination signal...");
        provbpf__destroy(skel);
        prov_refresh_records();
        syslog(LOG_INFO, "ProvBPF: Good bye!");
        exit(0);
    }
}

static void update_rlimit(void) {
    int err;
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};

    err = setrlimit(RLIMIT_MEMLOCK, &r);
    if (err) {
        syslog(LOG_ERR, "ProvBPF: Error while setting rlimit %d.", err);
        exit(err);
    }
}

static int init_machine_info(void) {
    int err, map_fd;
    struct utsname buffer;
    union long_prov_elt prov_machine;
    unsigned int key = 0;

    memset(&prov_machine, 0, sizeof(union long_prov_elt));

    /* we set parameters before attaching programs */
    set_id(skel, BOOT_ID_INDEX, get_boot_id());
    set_id(skel, MACHINE_ID_INDEX, get_machine_id());

    // set provenance metadata
    prov_machine.node_info.identifier.node_id.type = AGT_MACHINE;
    prov_machine.node_info.identifier.node_id.id = prov_next_id(NODE_ID_INDEX, skel);
    prov_machine.node_info.identifier.node_id.id = djb2_hash(PROVBPF_COMMIT);
    prov_machine.node_info.identifier.node_id.boot_id = get_boot_id();
    prov_machine.node_info.identifier.node_id.machine_id = get_machine_id();
    prov_machine.node_info.identifier.node_id.version = 0;

    // set release version
    prov_machine.machine_info.cam_major = PROVBPF_VERSION_MAJOR;
    prov_machine.machine_info.cam_minor = PROVBPF_VERSION_MINOR;
    prov_machine.machine_info.cam_patch = PROVBPF_VERSION_PATCH;

    // set git commit hash
    memcpy(&(prov_machine.machine_info.commit), PROVBPF_COMMIT, PROV_COMMIT_MAX_LENGTH);

    // retrieve and set utsname
    err = uname(&buffer);
    if (err<0) {
        syslog(LOG_ERR, "ProvBPF: Error while calling uname %d.", errno);
        return err;
    }
    memcpy(&(prov_machine.machine_info.utsname), &buffer, sizeof(struct new_utsname));

    map_fd = bpf_object__find_map_fd_by_name(skel->obj, "prov_machine_map");
    bpf_map_update_elem(map_fd, &key, &prov_machine, BPF_ANY);

    return 0;
}

static int init_policy(void) {
    int map_fd;
    struct capture_policy prov_policy;
    unsigned int key = 0;

    memset(&prov_policy, 0, sizeof(struct capture_policy));

  	prov_policy.should_duplicate = false;
  	prov_policy.should_compress_node = true;
  	prov_policy.should_compress_edge = true;

    map_fd = bpf_object__find_map_fd_by_name(skel->obj, "policy_map");
    bpf_map_update_elem(map_fd, &key, &prov_policy, BPF_ANY);

    return 0;
}

int main(void) {
    struct ring_buffer *ringbuf = NULL;
    int err, map_fd;

    syslog(LOG_INFO, "ProvBPF: Starting...");

    syslog(LOG_INFO, "ProvBPF: %s.", PROVBPF_VERSION_STR);
    syslog(LOG_INFO, "ProvBPF: commit %s.", PROVBPF_COMMIT);

    syslog(LOG_INFO, "ProvBPF: Registering signal handler...");
    signal(SIGTERM, sig_handler);

    syslog(LOG_INFO, "ProvBPF: Reading Configuration...");
    read_config();

    syslog(LOG_INFO, "ProvBPF: Setting rlimit...");
    update_rlimit();

    syslog(LOG_INFO, "ProvBPF: Open and loading...");
    skel = provbpf__open_and_load();
    if (!skel) {
        syslog(LOG_ERR, "ProvBPF: Failed loading bpf skeleton.");
        goto close_prog;
    }

    syslog(LOG_INFO, "ProvBPF: initializing machine information...");
    err = init_machine_info();
    if(err) {
        syslog(LOG_ERR, "ProvBPF: Failed initializing machine information.");
        goto close_prog;
    }

    syslog(LOG_INFO, "ProvBPF: initializing policy...");
    err = init_policy();
    if(err) {
        syslog(LOG_ERR, "ProvBPF: Failed initializing policy.");
        goto close_prog;
    }

    syslog(LOG_INFO, "ProvBPF: Attaching BPF programs...");
    err = provbpf__attach(skel);
    if (err) {
        syslog(LOG_ERR, "ProvBPF: Failed attaching %d.", err);
        goto close_prog;
    }

    /* Locate ring buffer */
    syslog(LOG_INFO, "ProvBPF: Locating the ring buffer...");
    map_fd = bpf_object__find_map_fd_by_name(skel->obj, "r_buf");
    if (map_fd < 0) {
        syslog(LOG_ERR, "ProvBPF: Failed loading ring buffer (%d).", map_fd);
        goto close_prog;
    }
    syslog(LOG_INFO, "ProvBPF: Setting up the ring buffer in userspace...");
    /* Create a new ring buffer handle in the userspace.
     * buf_process_entry is the callback function that
     * process the entry in the ring buffer. */
    prov_record_init();

    ringbuf = ring_buffer__new(map_fd, buf_process_entry, NULL, NULL);
    syslog(LOG_INFO, "ProvBPF: Start polling forever...");
    /* ring_buffer__poll polls for available data and consume records,
     * if any are available. Returns number of records consumed, or
     * negative number, if any of the registered callbacks returned error. */
    while (ring_buffer__poll(ringbuf, -1) >= 0) {
        prov_refresh_records();
    }

close_prog:
    provbpf__destroy(skel);
    return 0;
}
