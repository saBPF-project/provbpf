target := bpf_camflow

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

prepare: build_libbpf build_kernel

btf:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	cp -f vmlinux.h .circleci/_vmlinux.h

btf_circle:
	cp -f .circleci/_vmlinux.h vmlinux.h

kern:
	clang -O2 -Wall \
	-DPROV_FILTER_FILE_PERMISSION_OFF \
	-DPROV_FILTER_SOCKET_SENDMSG_OFF \
	-D__KERNEL__ -D__ASM_SYSREG_H \
	-Wno-unused-value -Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	-Wno-gnu-variable-sized-type-not-at-end \
	-Wno-address-of-packed-member -Wno-tautological-compare \
	-Wno-unknown-warning-option \
	-Iinclude \
	-target bpf -c $(target)_kern.c -o $(target)_kern.o

skel:
	bpftool gen skeleton $(target)_kern.o > $(target).skel.h

usr:
	clang utils.c -o utils.o -Iinclude -c
	clang types.c -o types.o -Iinclude -c
	clang spade.c -o spade.o -Iinclude -c
	clang w3c.c -o w3c.o -Iinclude -c
	clang record.c -o record.o -Iinclude -c
	clang configuration.c -o configuration.o -Iinclude -c
	clang id.c -o id.o -Iinclude -c
	clang service.c -o service.o -Iinclude -c
	clang -o provbpfd \
	service.o \
	record.o \
	id.o \
	configuration.o \
	spade.o \
	w3c.o \
	types.o \
	utils.o \
	-lbpf -lpthread -linih

usr_dbg:
	clang -g utils.c -o utils.o -Iinclude -c
	clang -g types.c -o types.o -Iinclude -c
	clang -g spade.c -o spade.o -Iinclude -c
	clang -g w3c.c -o w3c.o -Iinclude -c
	clang -g record.c -o record.o -Iinclude -c
	clang -g configuration.c -o configuration.o -Iinclude -c
	clang -g id.c -o id.o -Iinclude -c
	clang -g service.c -o service.o -Iinclude -c
	clang -g -o provbpfd \
	service.o \
	record.o \
	id.o \
	configuration.o \
	spade.o \
	w3c.o \
	types.o \
	-lbpf -lpthread -linih

all: clean btf kern skel usr

install:
	sudo cp --force ./provbpf.ini /etc/provbpf.ini
	sudo cp --force ./provbpfd /usr/bin/provbpfd
	sudo cp --force ./provbpfd.service /etc/systemd/system/provbpfd.service
	sudo systemctl enable provbpfd.service

start:
	sudo systemctl start provbpfd.service

stop:
	sudo systemctl stop provbpfd.service

uninstall:
	sudo systemctl stop provbpfd.service
	sudo systemctl disable provbpfd.service
	rm -f /etc/provbpf.ini
	rm -f /usr/bin/provbpfd
	rm -f /etc/systemd/system/provbpfd.service

run:
	rm -rf audit.log
	sudo ./provbpfd

run_valgrind: usr_dbg
	rm -rf audit.log
	sudo valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./provbpfd

rpm:
	mkdir -p ~/rpmbuild/{RPMS,SRPMS,BUILD,SOURCES,SPECS,tmp}
	cp -f ./provbpf.spec ~/rpmbuild/SPECS/provbpf.spec
	rpmbuild -bb provbpf.spec
	mkdir -p output
	cp ~/rpmbuild/RPMS/x86_64/* ./output

clean:
	rm -f *.o
	rm -f *.skel.h
	rm -rf vmlinux.h
	rm -rf output
