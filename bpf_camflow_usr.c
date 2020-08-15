/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/bpf.h>

#include "bpf_camflow.skel.h"

struct entry {
    uint32_t pid;
};

/* Callback function for ring buffer. */
static int buf_process_entry(void *ctx, void *data, size_t len) {
    struct entry *record;
    printf("Reading data of size %zu from the ring buffer...\n", len);
    /* data should be the ring buffer entry. */
    record = (struct entry*)data;
    printf("New pid from ring buffer: %u\n", record->pid);
    return 0;
}

int main(void) {
    struct bpf_camflow_kern *skel = NULL;
    struct ring_buffer *ringbuf = NULL;
    int err, map_fd;
    pid_t pid;
    unsigned int key = 0, value;
    
    printf("Starting...\n");
    
    skel = bpf_camflow_kern__open_and_load();
    if (!skel) {
        printf("Failed loading ...\n");
	printf("Kernel doesn't support this program type.\n");
	goto close_prog;
    }
    
    err = bpf_camflow_kern__attach(skel);
    if (err) {
        printf("Failed attach ... %d\n", err);
	goto close_prog;
    }
    
    //map_fd = bpf_object__find_map_fd_by_name(skel->obj, "task_map");
    //err = bpf_map_lookup_elem(map_fd, &key, &value);
    //printf("err: %d value: %d\n", err, value);

    // Consume data from ring buffer
    // Reference: https://elixir.bootlin.com/linux/v5.8/source/tools/testing/selftests/bpf/benchs/bench_ringbufs.c
    printf("Locating the ring buffer...\n");
    map_fd = bpf_object__find_map_fd_by_name(skel->obj, "r_buf");
    if (map_fd < 0) {
        printf("Failed to load the ring buffer... %d\n", map_fd);
	goto close_prog;
    }
    
    /* Create a new ring buffer handle in the userspace.
     * buf_process_entry is the callback function that
     * process the entry in the ring buffer. */
    ringbuf = ring_buffer__new(map_fd, buf_process_entry, NULL, NULL);

    /* Check which pid is being captured by the task_alloc hook. */
    pid = fork();
    if (pid == 0) {
        sleep(5);
        printf("Child process %u is running...\n", getpid());
        return 0;
    } else if (pid > 0) {
        printf("Parent process %u is running...\n", getpid());
	printf("Polling forever...\n");
        /* ring_buffer__poll: Poll for available data and consume records, 
         * if any are available. Returns number of records consumed, or
         * negative number, if any of the registered callbacks returned error. */
        while (ring_buffer__poll(ringbuf, -1) >= 0);
        /* If while loop is escapted, something must have gone wrong. */
        fprintf(stderr, "ring buffer polling failed!\n");
    } else {
        printf("fork() failed!\n");
	goto close_prog;
    }

close_prog:
    bpf_camflow_kern__destroy(skel);
    return 0;
}
