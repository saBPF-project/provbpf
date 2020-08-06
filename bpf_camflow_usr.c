/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/bpf.h>

#include "bpf_camflow.skel.h"

#define BUFFER_SIZE 10

// Get the least recently added item from the BPF Ring Buffer Map
unsigned int bpf_ring_buffer_get(int ring_buffer_fd) {
	int err;
	unsigned int entry, head_key = BUFFER_SIZE, tail_key = BUFFER_SIZE + 1, head_pointer_value, tail_pointer_value;

	err = bpf_map_lookup_elem(ring_buffer_fd, &head_key, &head_pointer_value);
	err = bpf_map_lookup_elem(ring_buffer_fd, &tail_key, &tail_pointer_value);
	err = bpf_map_lookup_elem(ring_buffer_fd, &tail_pointer_value, &entry);

	if (tail_pointer_value != head_pointer_value) {
		tail_pointer_value = (tail_pointer_value + 1) % BUFFER_SIZE;
		// Update tail_pointer_value
		err = bpf_map_update_elem(ring_buffer_fd, &tail_key, &tail_pointer_value, BPF_ANY);
	}

	return entry;
}

int main(void)
{
	struct bpf_camflow_kern *skel = NULL;
  int err;
	int map_fd, ring_buffer_fd;
	unsigned int key = 0, value;
	unsigned int head_key = BUFFER_SIZE, tail_key = BUFFER_SIZE + 1, head_pointer_value, tail_pointer_value, entry;

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
	map_fd = bpf_object__find_map_fd_by_name(skel->obj, "my_map");

	ring_buffer_fd = bpf_object__find_map_fd_by_name(skel->obj, "ring_buffer_map");

	err = bpf_map_lookup_elem(map_fd, &key, &value);
	printf("err: %d value: %d\n", err, value);

	// Print initial head pointer position
	err = bpf_map_lookup_elem(ring_buffer_fd, &head_key, &head_pointer_value);
	printf("ring_buf_err: %d head_pointer_value: %d\n", err, head_pointer_value);
	// Print initial tail pointer position
	err = bpf_map_lookup_elem(ring_buffer_fd, &tail_key, &tail_pointer_value);
	printf("ring_buf_err: %d tail_pointer_value: %d\n", err, tail_pointer_value);

  printf("Sleeping...\n");
  sleep(20);
  printf("Slept.\n");
	err = bpf_map_lookup_elem(map_fd, &key, &value);
	printf("err: %d value: %d\n", err, value);

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
