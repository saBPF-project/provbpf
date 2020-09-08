# camflow-bpf

Use this [vagrant VM](https://github.com/CamFlow/vagrant/tree/master/dev-fedora).
No need to build CamFlow.

## Setting things up

Getting submodules:
```
make submodule
```

Building libbpf:
```
make build_libbpf
```

Building latest fedora kernel:
```
make build_kernel
```

Building libprovenance:
```
make build_libprovenance
```

All of the build in one go:
```
make prepare
```

## Building and running

Building bpf kernel and user space program:
```
make all
```

Running bpf program:
```
make run
```
