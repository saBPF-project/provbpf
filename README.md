# camflow-bpf

Use this [vagrant VM](https://github.com/saBPF-project/provbpf-vagrant).

## Setting things up

Building libbpf:
```
make build_libbpf
```

Building latest fedora kernel:
```
make build_kernel
```

All of the build in one go:
```
make prepare
```

Delete the dependencies' build folders:
```
make delete_dependency
```

You should reboot the machine and make sure you boot under the correct kernel.

## Building and running

Building bpf kernel and user space program:
```
make all
```

Installing CamFlowBPF:
```
make install
```

Starting the service:
```
make start
```

Stopping the service:
```
make stop
```

Check [provbpf.ini](provbpf.ini) that can be edited at `/etc/provbpf.ini`.

Running bpf program:
```
make run
```
