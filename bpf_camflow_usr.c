/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <sys/resource.h>

#include "bpf_camflow.skel.h"
#include "linux/provenance.h"

#include "camflow_bpf_record.h"

/* Callback function called whenever a new ring
 * buffer entry is polled from the buffer. */
static int buf_process_entry(void *ctx, void *data, size_t len) {
    printf("Read data of size %zu\n", len);
    /* Every entry from the ring buffer should
     * be of type union prov_elt.
     */
    union prov_elt *prov = (union prov_elt*)data;

    printf("Task id is %u\n", prov->task_info.pid);
    printf("Unique is %lu\n", prov->task_info.utime);
    /* Userspace processing the provenance record. */
    prov_record(prov);

    return 0;
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
    ringbuf = ring_buffer__new(map_fd, buf_process_entry, NULL, NULL);
    printf("Start polling forever...\n");
    /* ring_buffer__poll polls for available data and consume records,
     * if any are available. Returns number of records consumed, or
     * negative number, if any of the registered callbacks returned error. */
    while (ring_buffer__poll(ringbuf, -1) >= 0);

	// Print final head pointer position
	err = bpf_map_lookup_elem(ring_buffer_fd, &head_key, &head_pointer_value);
	printf("ring_buf_err: %d head_pointer_value: %d\n", err, head_pointer_value);
	// Print final tail pointer position
	err = bpf_map_lookup_elem(ring_buffer_fd, &tail_key, &tail_pointer_value);
	printf("ring_buf_err: %d tail_pointer_value: %d\n", err, tail_pointer_value);

	// Print entry extracted from BPF Ring Buffer Map and tail pointer position
	entry = bpf_ring_buffer_get(ring_buffer_fd);
	printf("Extracted entry value from ring buffer: %d\n", entry);
	err = bpf_map_lookup_elem(ring_buffer_fd, &tail_key, &tail_pointer_value);
	printf("ring_buf_err: %d tail_pointer_value: %d\n", err, tail_pointer_value);

close_prog:
    bpf_camflow_kern__destroy(skel);
    return 0;
}
