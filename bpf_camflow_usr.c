/* SPDX-License-Identifier: GPL-2.0 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <sys/resource.h>

#include "bpf_camflow.skel.h"
#include "linux/provenance.h"

#include "camflow_bpf_record.h"
#include "camflow_bpf_id.h"

/* Callback function called whenever a new ring
 * buffer entry is polled from the buffer. */
static int buf_process_entry(void *ctx, void *data, size_t len) {
    printf("Read data of size %zu\n", len);
    /* Every entry from the ring buffer should
     * be of type union prov_elt.
     */
    union prov_elt *prov = (union prov_elt*)data;

    printf("Task id is %u\n", prov->task_info.pid);
    printf("Unique is %lu\n", prov->task_info.identifier.node_id.id);
    /* Userspace processing the provenance record. */
    prov_record(prov);

    return 0;
}

void set_id(struct bpf_camflow_kern *skel, uint32_t index, uint64_t value) {
    int map_fd;
    struct id_elem id;
    map_fd = bpf_object__find_map_fd_by_name(skel->obj, "ids_map");
    id.id = value;
    bpf_map_update_elem(map_fd, &index, &id, BPF_ANY);
}

int main(void) {
    struct bpf_camflow_kern *skel = NULL;
    struct ring_buffer *ringbuf = NULL;
    int err, map_fd;
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    pid_t pid;
    unsigned int key = 0, value;

    printf("Starting...\n");

    printf("Setting rlimit...\n");
    err = setrlimit(RLIMIT_MEMLOCK, &r);
    if (err) {
        printf("Error while setting rlimit %d\n", err);
        return err;
    }

    printf("Open and loading...\n");
    skel = bpf_camflow_kern__open_and_load();
    if (!skel) {
        printf("Failed loading ...\n");
        printf("Kernel doesn't support this program type.\n");
        goto close_prog;
    }

    /* we set parameters before attaching programs */
    // TODO copy existing CamFlow code to get those values.
    set_id(skel, BOOT_ID_INDEX, get_boot_id());
    set_id(skel, MACHINE_ID_INDEX, get_machine_id());

    printf("Attaching BPF programs ...\n");
    err = bpf_camflow_kern__attach(skel);
    if (err) {
        printf("Failed attach ... %d\n", err);
        goto close_prog;
    }

    //map_fd = bpf_object__find_map_fd_by_name(skel->obj, "task_map");
    //err = bpf_map_lookup_elem(map_fd, &key, &value);
    //printf("err: %d value: %d\n", err, value);

    /* Locate ring buffer */
    printf("Locating the ring buffer...\n");
    map_fd = bpf_object__find_map_fd_by_name(skel->obj, "r_buf");
    if (map_fd < 0) {
        printf("Failed loading ring buffer (%d)\n", map_fd);
        goto close_prog;
    }
    printf("Setting up the ring buffer in userspace...\n");
    /* Create a new ring buffer handle in the userspace.
     * buf_process_entry is the callback function that
     * process the entry in the ring buffer. */
    prov_init();
    ringbuf = ring_buffer__new(map_fd, buf_process_entry, NULL, NULL);
    printf("Start polling forever...\n");
    /* ring_buffer__poll polls for available data and consume records,
     * if any are available. Returns number of records consumed, or
     * negative number, if any of the registered callbacks returned error. */
    while (ring_buffer__poll(ringbuf, -1) >= 0) {
        prov_refresh_records();
    }

close_prog:
    bpf_camflow_kern__destroy(skel);
    return 0;
}
