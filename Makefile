target := bpf_camflow
kernel-version := 5.8

submodule:
	git submodule update --init --recursive

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

build_threadpool:
	cd threadpool && $(MAKE) all

prepare: submodule build_libbpf build_kernel build_libprovenance build_threadpool

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
	clang camflow_bpf_configuration.c -o camflow_bpf_configuration.o \
	-Icamflow-dev/include/uapi -Iinclude -c
	clang $(target)_usr.c -o $(target)_usr.o -Icamflow-dev/include/uapi \
	-Iinclude -Ithreadpool/C-Thread-Pool -c
	clang -o provbpfd \
	$(target)_usr.o \
	camflow_bpf_record.o \
	camflow_bpf_id.o \
	camflow_bpf_configuration.o \
	threadpool/thpool.a \
	-lbpf -lprovenance -lpthread -linih

usr_dbg:
	clang -g camflow_bpf_record.c -o camflow_bpf_record.o \
	-Icamflow-dev/include/uapi -Iinclude -c
	clang -g camflow_bpf_id.c -o camflow_bpf_id.o \
	-Icamflow-dev/include/uapi -Iinclude -c
	clang -g camflow_bpf_configuration.c -o camflow_bpf_configuration.o \
	-Icamflow-dev/include/uapi -Iinclude -c
	clang -g $(target)_usr.c -o $(target)_usr.o -Icamflow-dev/include/uapi \
	-Iinclude -Ithreadpool/C-Thread-Pool -c
	clang -g -o provbpfd \
	$(target)_usr.o \
	camflow_bpf_record.o \
	camflow_bpf_id.o \
	camflow_bpf_configuration.o \
	threadpool/thpool.a \
	-lbpf -lprovenance -lpthread -linih

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
