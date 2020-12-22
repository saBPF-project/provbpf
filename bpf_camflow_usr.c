/* SPDX-License-Identifier: GPL-2.0 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <sys/resource.h>
#include <sys/types.h>

#include "bpf_camflow.skel.h"
#include "linux/provenance.h"

#include "camflow_bpf_record.h"
#include "camflow_bpf_id.h"

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
    int err, map_fd, search_map_fd, res;
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    unsigned int key = 0, value;
    uint64_t search_map_key, prev_search_map_key;
    union prov_elt search_map_value;
    pid_t current_pid;

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

    // Initialize provenance policy
    struct capture_policy prov_policy;

    printf("Provenance: policy initialization started...\n");
    prov_policy.prov_enabled = true;
  	prov_policy.should_duplicate = false;
  	prov_policy.should_compress_node = true;
  	prov_policy.should_compress_edge = true;
#ifdef CONFIG_SECURITY_PROVENANCE_BOOT
  	prov_policy.prov_all = true;
#else
  	prov_policy.prov_all = false;
#endif

    map_fd = bpf_object__find_map_fd_by_name(skel->obj, "policy_map");
    bpf_map_update_elem(map_fd, &key, &prov_policy, BPF_ANY);
    printf("Provenance: policy initialization finished.\n");

    printf("Attaching BPF programs ...\n");
    err = bpf_camflow_kern__attach(skel);
    if (err) {
        printf("Failed attach ... %d\n", err);
        goto close_prog;
    }

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

    current_pid = getpid();

    printf("Searching task_map for current process...\n");
    search_map_fd = bpf_object__find_map_fd_by_name(skel->obj, "task_map");
    if (search_map_fd < 0) {
      printf("Failed loading task_map (%d)\n", search_map_fd);
      goto close_prog;
    }

    search_map_key = -1;
    while (bpf_map_get_next_key(search_map_fd, &prev_search_map_key, &search_map_key) == 0) {
      res = bpf_map_lookup_elem(search_map_fd, &search_map_key, &search_map_value);
      if (res > -1) {
          if (search_map_value.task_info.pid == current_pid) {
            set_opaque(&search_map_value);
            bpf_map_update_elem(search_map_fd, &search_map_key, &search_map_value, BPF_EXIST);
            break;
          }
      }
      prev_search_map_key = search_map_key;
    }
    close(search_map_fd);
    printf("Done searching. Current process pid: %d has been set opaque...\n", current_pid);

    printf("Searching cred_map for current cred...\n");
    search_map_fd = bpf_object__find_map_fd_by_name(skel->obj, "cred_map");
    if (search_map_fd < 0) {
      printf("Failed loading task_map (%d)\n", search_map_fd);
      goto close_prog;
    }

    search_map_key = -1;
    while (bpf_map_get_next_key(search_map_fd, &prev_search_map_key, &search_map_key) == 0) {
      res = bpf_map_lookup_elem(search_map_fd, &search_map_key, &search_map_value);
      if (res > -1) {
          if (search_map_value.proc_info.tgid == current_pid) {
            set_opaque(&search_map_value);
            bpf_map_update_elem(search_map_fd, &search_map_key, &search_map_value, BPF_EXIST);
            printf("Done searching. Current cred tgid: %d has been set opaque...\n", current_pid);
            break;
          }
      }
      prev_search_map_key = search_map_key;
    }
    close(search_map_fd);

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
