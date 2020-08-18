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

Getting dependencies:
```
git submodule update --init
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
