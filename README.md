# camflow-bpf

Use this [vagrant VM](https://github.com/CamFlow/vagrant/tree/master/dev-fedora).
No need to build CamFlow.

## Setting things up

Building libbpf:
```
make build_libbpf
```

Building latest fedora kernel:
```
make build_kernel
```

Building mainline vanilla kernel:
```
make build_mainline
```

`make all`

`make run`
