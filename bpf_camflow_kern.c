/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct linux_binprm {
        int argc, envc;
} __attribute__((preserve_access_index));

SEC("lsm/bprm_committing_creds")
int BPF_PROG(bprm_committing_creds, struct linux_binprm *bprm)
{
        bpf_printk("exec!\n");
        return 0;
}

char _license[] SEC("license") = "GPL";
