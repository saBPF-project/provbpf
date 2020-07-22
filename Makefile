target := bpf_camflow

kern:
	clang -O2 -Wall -target bpf -c $(target)_kern.c -o $(target)_kern.o

skel:
	bpftool gen skeleton $(target)_kern.o > $(target).skel.h

usr:
	clang $(target)_usr.c -lbpf -o $(target)_usr.o

run:
	sudo ./$(target)_usr.o

all: kern skel usr

clean:
	rm -f *.o
	rm -f *.skel.h
