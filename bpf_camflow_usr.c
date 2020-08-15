/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/bpf.h>

#include "bpf_camflow.skel.h"
#include "provenance.h"

static int buf_process_entry(void *ctx, void *data, size_t len)
{
  printf("Read data of size %zu\n", len);
  union prov_elt *prov = (union prov_elt*)data;
  printf("Task id is %u\n", prov->task_info.pid);
	return 0;
}

int main(void) {
  struct bpf_camflow_kern *skel = NULL;
  struct ring_buffer *ringbuf = NULL;
  int err;
  int map_fd;
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

  printf("Locating map...\n");
  map_fd = bpf_object__find_map_fd_by_name(skel->obj, "r_buf");
  if (map_fd < 0) {
    printf("Failed loading map ... %d\n", map_fd);
    goto close_prog;
  }
  printf("Setting up the ring buffer...\n");
  ringbuf = ring_buffer__new(map_fd, buf_process_entry, NULL, NULL);
  printf("Polling...\n");
  while (ring_buffer__poll(ringbuf, -1) >= 0);

close_prog:
  bpf_camflow_kern__destroy(skel);
  return 0;
}
