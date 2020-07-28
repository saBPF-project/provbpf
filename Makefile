target := bpf_camflow

build_libbpf:
	cd ~ && git clone https://github.com/libbpf/libbpf
	cd ~/libbpf/src && make
	cd ~/libbpf/src && sudo $(MAKE) install

build_kernel:
	cd ~ && git clone -b f32 --single-branch git://git.kernel.org/pub/scm/linux/kernel/git/jwboyer/fedora.git
	cd ~/fedora && $(MAKE) olddefconfig
	cd ~/fedora && sed -i -e "s/CONFIG_LSM=\"yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor\"/CONFIG_LSM=\"yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor,bpf\"/g" .config
	cd ~/fedora && $(MAKE) -j16
	cd ~/fedora && sudo $(MAKE) modules_install
	cd ~/fedora && sudo $(MAKE) install

prepare: build_libbpf build_kernel

btf:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

kern:
	clang -O2 -Wall \
	-D__KERNEL__ -D__ASM_SYSREG_H \
  -Wno-unused-value -Wno-pointer-sign \
  -Wno-compare-distinct-pointer-types \
  -Wno-gnu-variable-sized-type-not-at-end \
  -Wno-address-of-packed-member -Wno-tautological-compare \
  -Wno-unknown-warning-option \
	-target bpf -c $(target)_kern.c -o $(target)_kern.o

skel:
	bpftool gen skeleton $(target)_kern.o > $(target).skel.h

usr:
	clang $(target)_usr.c -lbpf -o $(target)_usr.o

run:
	sudo ./$(target)_usr.o

all: clean btf kern skel usr

clean:
	rm -f *.o
	rm -f *.skel.h
	rm -rf vmlinux.h
