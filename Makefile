target := bpf_camflow

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
