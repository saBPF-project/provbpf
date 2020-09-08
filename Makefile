target := bpf_camflow
kernel-version := 5.8

submodule:
	git submodule update --init

build_libbpf:
	cd ~ && git clone https://github.com/libbpf/libbpf
	cd ~/libbpf/src && make
	cd ~/libbpf/src && sudo $(MAKE) install

build_kernel:
	cd ~ && git clone -b f32 --single-branch git://git.kernel.org/pub/scm/linux/kernel/git/jwboyer/fedora.git
	cd ~/fedora && $(MAKE) olddefconfig
	cd ~/fedora && sed -i -e "s/CONFIG_LSM=\"yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor\"/CONFIG_LSM=\"yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor,bpf\"/g" .config
	cd ~/fedora && sed -i -e "s/# CONFIG_BPF_LSM is not set/CONFIG_BPF_LSM=y/g" .config
	cd ~/fedora && $(MAKE) -j16
	cd ~/fedora && sudo $(MAKE) modules_install
	cd ~/fedora && sudo $(MAKE) install

build_libprovenance:
	cd libprovenance/src && sed -i -e "s/INCLUDES = -I..\/include/INCLUDES = -I..\/include -I..\/..\/camflow-dev\/include\/uapi/g" Makefile
	cd libprovenance && $(MAKE) prepare
	cd libprovenance && $(MAKE) all
	cd libprovenance && $(MAKE) install
	cd libprovenance/src && sed -i -e "s/INCLUDES = -I..\/include -I..\/..\/camflow-dev\/include\/uapi/INCLUDES = -I..\/include/g" Makefile

prepare: build_libbpf build_kernel build_libprovenance

btf:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	cp -f vmlinux.h .circleci/_vmlinux.h

btf_circle:
	cp -f .circleci/_vmlinux.h vmlinux.h

kern:
	clang -O2 -Wall \
	-D__KERNEL__ -D__ASM_SYSREG_H \
	-Wno-unused-value -Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	-Wno-gnu-variable-sized-type-not-at-end \
	-Wno-address-of-packed-member -Wno-tautological-compare \
	-Wno-unknown-warning-option \
	-Icamflow-dev/include/uapi \
	-Iinclude \
	-target bpf -c $(target)_kern.c -o $(target)_kern.o

skel:
	bpftool gen skeleton $(target)_kern.o > $(target).skel.h

usr:
	clang camflow_bpf_record.c -o camflow_bpf_record.o \
	-Icamflow-dev/include/uapi -Iinclude -c
	clang camflow_bpf_id.c -o camflow_bpf_id.o \
	-Icamflow-dev/include/uapi -Iinclude -c
	clang $(target)_usr.c -o $(target)_usr.o -Icamflow-dev/include/uapi \
	-Iinclude -c
	clang -o bpf_camflow $(target)_usr.o camflow_bpf_record.o camflow_bpf_id.o -lbpf -lprovenance -lpthread

run:
	sudo ./bpf_camflow

all: clean btf kern skel usr

clean:
	rm -f *.o
	rm -f *.skel.h
	rm -rf vmlinux.h
