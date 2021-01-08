/* SPDX-License-Identifier: GPL-2.0 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <signal.h>

#include "bpf_camflow.skel.h"
#include "linux/provenance.h"

#include "camflow_bpf_record.h"
#include "camflow_bpf_id.h"
#include "camflow_bpf_configuration.h"


#define DM_AGENT                                0x1000000000000000UL
/* NODE IS LONG*/
#define ND_LONG                                 0x0400000000000000UL
#define AGT_MACHINE                             (DM_AGENT | ND_LONG | (0x0000000000000001ULL << 4))

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

static __always_inline uint64_t prov_next_id(uint32_t key, struct bpf_camflow_kern *skel)	{
    int map_fd = bpf_object__find_map_fd_by_name(skel->obj, "ids_map");
    if (map_fd < 0) {
      printf("Failed loading ids_map (%d)\n", map_fd);
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

static __always_inline uint64_t prov_get_id(uint32_t key, struct bpf_camflow_kern *skel) {
    int map_fd = bpf_object__find_map_fd_by_name(skel->obj, "ids_map");
    if (map_fd < 0) {
      printf("Failed loading ids_map (%d)\n", map_fd);
      return 0;
    }

    struct id_elem val;
    int res = bpf_map_lookup_elem(map_fd, &key, &val);
    if (res == -1)
        return 0;
    return val.id;
}

/* djb2 hash implementation by Dan Bernstein */
static inline uint64_t djb2_hash(const char *str)
{
	uint64_t hash = 5381;
	int c = *str;

	while (c) {
		hash = ((hash << 5) + hash) + c;
		c = *++str;
	}
	return hash;
}

static struct bpf_camflow_kern *skel = NULL;

void sig_handler(int sig) {
    if (sig == SIGTERM) {
        printf("Received termination signal...\n");
        prov_refresh_records();
        bpf_camflow_kern__destroy(skel);
        exit(0);
    }
}

int main(void) {
    struct ring_buffer *ringbuf = NULL;
    int err, map_fd, search_map_fd, res;
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    unsigned int key = 0, value;
    uint64_t search_map_key, prev_search_map_key;
    union prov_elt search_map_value;
    pid_t current_pid;

    printf("Starting...\n");

    printf("Registering signal handler...\n");
    signal(SIGTERM, sig_handler);

    printf("Reading Configuration...\n");
    read_config();

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

    printf("Provenance: prov_machine initialization started...\n");
    union long_prov_elt prov_machine;

    prov_machine.machine_info.cam_major = CAMFLOW_VERSION_MAJOR;
    prov_machine.machine_info.cam_minor = CAMFLOW_VERSION_MINOR;
    prov_machine.machine_info.cam_patch = CAMFLOW_VERSION_PATCH;

    __builtin_memcpy(&(prov_machine.machine_info.commit), CAMFLOW_COMMIT, PROV_COMMIT_MAX_LENGTH);

    prov_machine.node_info.identifier.node_id.type = AGT_MACHINE;
    prov_machine.node_info.identifier.node_id.id = prov_next_id(NODE_ID_INDEX, skel);
    prov_machine.node_info.identifier.node_id.boot_id = prov_get_id(BOOT_ID_INDEX, skel);
    prov_machine.node_info.identifier.node_id.machine_id = prov_get_id(MACHINE_ID_INDEX, skel);
    prov_machine.node_info.identifier.node_id.version = 1;

    struct utsname buffer;

    int result = uname(&buffer);

    if (result == -1) {
        printf("Something went wrong...\n");
        return 0;
    }

    __builtin_memcpy(&(prov_machine.machine_info.utsname), &buffer, sizeof(struct new_utsname));

    prov_machine.node_info.identifier.node_id.id = djb2_hash(CAMFLOW_COMMIT);
    prov_machine.node_info.identifier.node_id.boot_id = get_boot_id();
    prov_machine.node_info.identifier.node_id.machine_id = get_machine_id();

    map_fd = bpf_object__find_map_fd_by_name(skel->obj, "prov_machine_map");
    bpf_map_update_elem(map_fd, &key, &prov_machine, BPF_ANY);

    printf("Provenance: prov_machine initialization ended...\n");

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
