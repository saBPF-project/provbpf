# camflow-bpf

`make all`

`make run`

Bogdan, see if you can fix the error with make run.

```
sudo ./bpf_camflow_usr.o
Starting...
libbpf: Error in bpf_object__probe_global_data():Operation not permitted(1). Couldn't create simple array map.
libbpf: load bpf program failed: Operation not permitted
libbpf: permission error while running as root; try raising 'ulimit -l'? current value: 64.0 KiB
libbpf: failed to load program 'lsm/bprm_committed_creds'
libbpf: failed to load object 'bpf_camflow_kern'
libbpf: failed to load BPF skeleton 'bpf_camflow_kern': -1
Failed loading ...
```

Adding this line in ` /etc/security/limits.conf` fix the issue:
```
*                -       memlock         unlimited
```

It seems it can be done in the user space program, see here: http://patchwork.ozlabs.org/project/netdev/patch/20190128191613.11705-5-maciejromanfijalkowski@gmail.com/

New problem:
```
sudo ./bpf_camflow_usr.o
Starting...
libbpf: load bpf program failed: Invalid argument
libbpf: failed to load program 'lsm/bprm_committed_creds'
libbpf: failed to load object 'bpf_camflow_kern'
libbpf: failed to load BPF skeleton 'bpf_camflow_kern': -22
Failed loading ...
```

If one run this appear (via `dmesg`):
```

[  224.654405] **********************************************************
[  224.654681] **   NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE   **
[  224.654968] **                                                      **
[  224.655174] ** trace_printk() being used. Allocating extra memory.  **
[  224.655364] **                                                      **
[  224.655597] ** This means that this is a DEBUG kernel and it is     **
[  224.655817] ** unsafe for production use.                           **
[  224.656013] **                                                      **
[  224.656197] ** If you see this message and you are not debugging    **
[  224.656387] ** the kernel, report this immediately to your vendor!  **
[  224.656571] **                                                      **
[  224.656755] **   NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE   **
[  224.656938] **********************************************************
```

When removing the `bpf_printk` get the following error:
```
sudo ./bpf_camflow_usr.o
Starting...
libbpf: load bpf program failed: Invalid argument
libbpf: failed to load program 'lsm/bprm_committed_creds'
libbpf: failed to load object 'bpf_camflow_kern'
libbpf: failed to load BPF skeleton 'bpf_camflow_kern': -4010
Failed loading ...
```

Simpified code give:
```
sudo ./bpf_camflow_usr.o
Starting...
libbpf: load bpf program failed: Invalid argument
libbpf: failed to load program '.text'
libbpf: failed to load object 'bpf_camflow_kern'
libbpf: failed to load BPF skeleton 'bpf_camflow_kern': -22
Failed loading ...
```

It may be errors in the way the code to be loaded is compiled. Need to investigate.
i.e. modify this `clang -O2 -Wall -target bpf -c $(target)_kern.c -o $(target)_kern.o`
