/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/bpf.h>

#include "bpf_camflow.skel.h"

int main(void) {
    struct bpf_camflow_kern *skel = NULL;
    int err;
    int map_fd;
    unsigned int key = 0, value;
    
    printf("Starting...\n");

    skel = bpf_camflow_kern__open_and_load();
    if (!skel) {
        printf("Failed loading ...\n");
	printf("LIBBPF_ERRNO__PROGTYPE: %d\n", LIBBPF_ERRNO__PROGTYPE);
	printf("Kernel doesn't support this program type.\n");
	goto close_prog;
    }
    
    err = bpf_camflow_kern__attach(skel);
    if (err) {
        printf("Failed attach ... %d\n", err);
	goto close_prog;
    }
    
    map_fd = bpf_object__find_map_fd_by_name(skel->obj, "task_map");
    //err = bpf_map_lookup_elem(map_fd, &key, &value);
    //printf("err: %d value: %d\n", err, value);

close_prog:
    bpf_camflow_kern__destroy(skel);
    
    return 0;
}
