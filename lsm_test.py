from bcc import BPF

# define BPF program

b = BPF(text="""
LSM_PROBE(bpf, int cmd, union bpf_attr *uattr, unsigned int size) {
    bpf_trace_printk("Hello\\n");
    return 0;
}""")
# depending on CONFIG_BPF_LSM being compiled in
try:
    b.load_func("lsm__bpf", BPF.LSM)
    print("DEBUG: LSM loaded")
except:
    print("DEBUG: Exception")
    pass
