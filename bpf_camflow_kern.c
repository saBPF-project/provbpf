#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("lsm/bprm_committed_creds")
int test_int_hook()
{
  bpf_printk("bprm_committed_creds was called");
  return 0;
}
