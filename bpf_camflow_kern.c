#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

int bpf_prog(void *ctx) {
  bpf_printk("Hello World!");
  return 0;
}
