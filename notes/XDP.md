# Detecting network packets using XDP

## Sources

Linux kernel XDP example, kernel-space: [xdp_sample_pkts_kern.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/samples/bpf/xdp_sample_pkts_kern.c)
Linux kernel XDP example, user-space: [xdp_sample_pkts_user.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/samples/bpf/xdp_sample_pkts_user.c)

Example XDP program, user-space: [xdp_pass_user.c](https://github.com/xdp-project/xdp-tutorial/blob/master/basic01-xdp-pass/xdp_pass_user.c)
Example XDP program, getting BPF program fd by title: [xdp_loader.c](https://github.com/xdp-project/xdp-tutorial/blob/master/basic02-prog-by-name/xdp_loader.c)

## Step 1 - Creating the BPF Program
In `kern.c` create program:
```
SEC("xdp")
int xdp_sample_prog(struct xdp_md *ctx) {
    return XDP_DROP;
}
```

This will be saved after `make all` into the skeleton file `provbpf.skel.h`
in `skel.progs->xdp_sample_prog`.

## Step 2 - Attaching the BPF Program into the kernel from userspace
### Attempt 1 - Attach using `iproute2`

- Use `sudo ip link set dev lo xdpgeneric obj provbpf.o sec xdp` to attach the BPF Program under section `SEC("xdp")` to the loopback network device `lo`.
- To check if the BPF Program has been attached: `ip link show dev lo`
- Alternatively, one can use `sudo bpftool net list dev lo`
- Detach from `lo` using `sudo ip link set dev lo xdpgeneric off`.

*Note:* BTF option enabled issues a warning when attaching the XDP program using `iproute2`
The BTF option embeds the source file path in the .BTF section which triggers the error at runtime. See: [here](https://github.com/xdp-project/xdp-tutorial/issues/38)
Disabling the BTF option is achieved by removing the `-g` flag from the `clang` command for compiling
the kernel-space program.

### Attempt 2 - Attach using `service.c`

### Steps to use the XDP hook in `service.c`
1. Set XDP Flags to `~XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE`
(i.e. force attach an XDP program to a network device even if an XDP program is
    already attached to it and use socket buffer mode)
1. Attach XDP program to network device (e.g. `lo`)
