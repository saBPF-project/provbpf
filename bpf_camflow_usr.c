/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "bpf_camflow.skel.h"

int main(void)
{
	struct bpf_camflow_kern *skel = NULL;
  int err;

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

  printf("Sleeping...\n");
  sleep(20);
  printf("Slept.\n");

close_prog:
	bpf_camflow_kern__destroy(skel);
  return 0;
}
