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
