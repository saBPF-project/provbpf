# Experiment 1 Setup Instructions
## Kernel Code
`bpf_camflow_kern.c`

```
/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

struct bpf_map_def SEC("maps") my_map = {
        .type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(u32),
        .value_size = sizeof(u32),
        .max_entries = 1,
};

static __always_inline void count(void *map)
{
	u32 key = 0;
	u32 *value, init_val = 1;

  // retrieve value of element 0
	value = bpf_map_lookup_elem(map, &key);
  // increment if exists, otherwise insert
	if (value)
		*value += 1;
	else
		bpf_map_update_elem(map, &key, &init_val, BPF_NOEXIST);
}

SEC("lsm/task_alloc")
int BPF_PROG(task_alloc, struct task_struct *task, unsigned long clone_flags)
{
  count(&my_map);
	return 0;
}
```

## User Code
`bpf_camflow_usr.c`

```
/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/bpf.h>

#include "bpf_camflow.skel.h"

int main(void)
{
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
	map_fd = bpf_object__find_map_fd_by_name(skel->obj, "my_map");

	err = bpf_map_lookup_elem(map_fd, &key, &value);
	printf("err: %d value: %d\n", err, value);
  printf("Sleeping...\n");
  sleep(20);
  printf("Slept.\n");
	err = bpf_map_lookup_elem(map_fd, &key, &value);
	printf("err: %d value: %d\n", err, value);

close_prog:
	bpf_camflow_kern__destroy(skel);
  return 0;
}
```

## Setup
1. Run `make prepare` and `sudo reboot now`
2. Boot into new kernel
3. Run `make all` and `make run`
4. While the `make run` command is executing open a new terminal and run a command (e.g. `ls`)
5. The counter stored in the `BPF_MAP_TYPE_ARRAY` will increment

## Example Output
```
sudo ./bpf_camflow_usr.o
Starting...
err: 0 value: 0
Sleeping...
Slept.
err: 0 value: 1
```
