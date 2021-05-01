prepare:
	mkdir -p ~/build
	cd ~/build && git clone https://github.com/tfjmp/provbpf-kernel.git
	cd ~/build/provbpf-kernel && $(MAKE) prepare_camflow
	cd ~/build/provbpf-kernel && $(MAKE) config_camflow
	cd ~/build/provbpf-kernel && $(MAKE) build
	cd ~/build/provbpf-kernel && $(MAKE) install

delete_dependency:
	rm -rf ~/build/linux-stable
	rm -rf ~/build/provbpf-kernel

btf:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/kern/vmlinux.h
	cp -f include/kern/vmlinux.h .circleci/_vmlinux.h

btf_circle:
	cp -f .circleci/_vmlinux.h include/kern/vmlinux.h

kern:
	clang -O2 -Wall \
	-DPROV_FILTER_IP_OUTPUT_OFF \
	-DPROV_FILTER_FILE_PERMISSION_OFF \
	-DPROV_FILTER_SOCKET_SENDMSG_OFF \
	-D__KERNEL__ -D__ASM_SYSREG_H \
	-Wno-unused-value -Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	-Wno-gnu-variable-sized-type-not-at-end \
	-Wno-address-of-packed-member -Wno-tautological-compare \
	-Wno-unknown-warning-option \
	-Iinclude \
	-target bpf -g -c kern.c -o provbpf.o

skel:
	bpftool gen skeleton provbpf.o > include/usr/provbpf.skel.h

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

update_commit:
	ruby ./scripts/update_commit.rb

remove_commit:
	ruby ./scripts/remove_commit.rb

all: clean btf update_commit kern skel usr remove_commit

install:
	sudo cp --force ./provbpf.ini /etc/provbpf.ini
	sudo cp --force ./provbpfd /usr/bin/provbpfd
	sudo cp --force ./provbpfd.service /etc/systemd/system/provbpfd.service
	sudo systemctl enable provbpfd.service

start:
	sudo systemctl start provbpfd.service

stop:
	sudo systemctl stop provbpfd.service

status:
	sudo systemctl status provbpfd.service

uninstall:
	sudo systemctl stop provbpfd.service
	sudo systemctl disable provbpfd.service
	sudo rm -f /etc/provbpf.ini
	sudo rm -f /usr/bin/provbpfd
	sudo rm -f /etc/systemd/system/provbpfd.service

tc:
	sudo tc filter del dev eth0 egress
	sudo tc filter add dev eth0 egress bpf da obj provbpf.o sec classifier

run:
	rm -rf audit.log
	sudo provbpfd

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
	rm -f include/usr/provbpf.skel.h
	rm -f include/kern/vmlinux.h
	rm -rf output
