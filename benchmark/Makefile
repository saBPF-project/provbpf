prepare_lmbench:
	@echo "Preparing lmbench"
	mkdir -p build
	cd build && git clone https://github.com/dmonakhov/lmbench.git
	cd build/lmbench && git checkout eb0d55e8999d1275da480aff0fca98805e55916e

prepare_unixbench:
	@echo "Preparing unixbench"
	mkdir -p build
	cd build && git clone https://github.com/kdlucas/byte-unixbench.git
	cd build/byte-unixbench && git checkout aeed2ba662a9220089aee33be4123481dab0b524

prepare_pgbench:
	@echo "Preparing pgbench"
	pgbench -i -s 70 bench2

prepare_postmark:
	@echo "Preparing postmark"
	mkdir -p build/postmark
	cp -f src/postmark-1_5.c build/postmark/postmark-1_5.c
	cd build/postmark && cc -o postmark postmark-1_5.c
	@echo "Please ignore warning"

prepare:prepare_lmbench prepare_unixbench prepare_pgbench prepare_postmark

service_off:
	-sudo systemctl stop camflowd.service

whole:
	sudo camflow -e true
	sudo camflow -a true

selective:
	sudo camflow -e true
	sudo camflow -a false

off:
	sudo camflow -e false
	sudo camflow -a false

run_lmbench:
	@echo "Running lmbench..."
	mkdir -p results
	cd build/lmbench && make results
	cd build/lmbench && make rerun
	#cd build/lmbench/results/ && make > ../../../results/lmbench.txt

run_unixbench:
	@echo "Running unixbench..."
	mkdir -p results
	cd build/byte-unixbench/UnixBench && ./Run > ../../../results/unixbench.txt

run_postmark:
	@echo "set size 4096 102400"
	@echo "set subdirectories 10"
	@echo "set number 4500"
	@echo "set transactions 1500000"
	cd build/postmark && ./postmark

run_kernel:
	 phoronix-test-suite benchmark pts/build-linux-kernel-1.10.2

run_R:
	phoronix-test-suite benchmark pts/rbenchmark-1.0.3

run_unpack:
	phoronix-test-suite benchmark pts/unpack-linux-1.1.1

run_apache:
	phoronix-test-suite benchmark pts/apache-1.7.2

run_nginx:
	phoronix-test-suite benchmark pts/nginx-1.2.2

run_mcperf:
	phoronix-test-suite benchmark pts/mcperf-1.4.0

run_phpbench:
	phoronix-test-suite benchmark pts/phpbench-1.1.6

run_pybench:
	phoronix-test-suite benchmark pts/pybench-1.1.3

run_redis:
	phoronix-test-suite benchmark pts/redis-1.3.0

run_pgbench:
	phoronix-test-suite benchmark pts/pgbench-1.10.1

run_network:
	phoronix-test-suite benchmark pts/network-loopback-1.0.3

run: run_lmbench run_unixbench run_pgbench run_postmark run_kernel run_R run_unpack run_apache

clean:
	rm -rf build
	rm -rf results
