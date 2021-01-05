# Benchmark

## Setting Up Benchmarking Tools

### Installing Dependencies - Fedora 

    sudo dnf install phoronix-test-suite postgresql-contrib postgresql-server perl-Time-HiRes expat-devel libtirpc-devel

### Creating a Database for pgbench (REMOVE IF NOT RUNNING PGBENCH)
pgbench is a benchmark tool for PostgreSQL. So before we initialize pgbench, we need to create a PostgreSQL database. In the `psql shell`:

    CREATE DATABASE <dbname>;
    CREATE USER <username>; 
    GRANT <permissions> ON DATABASE <dbname> TO <username>;

### LMbench - Fedora 28 and above
Since [Fedora 28](https://fedoraproject.org/wiki/Releases/28/ChangeSet#Removal_of_Sun_RPC_Interfaces_From_glibc), the Sun RPC interfaces have been removed from glibc. As a result, the compilation of LMbench returns an error because it is still reliant on the Sun RPC support. To solve this problem, add the following lines to `script/build`:

    LDLIBS="${LDLIBS} -ltirpc"
    CFLAGS="${CFLAGS} -I/usr/include/tirpc"

### Phoronix mcperf-1.3.0
The pts/mcperf-1.3.0 uses memcached-1.6.0, where a bug in 'crc32c' causes the phoronix installer to return an error. The bug has been fixed since [memcached-1.6.1](https://github.com/memcached/memcached/wiki/ReleaseNotes161), our workaround is to replace the memcached-1.6.0 tarball with the latest release at the time of writing --- [memcached-1.6.9](https://github.com/memcached/memcached/wiki/ReleaseNotes169).

### Building and Initializing
Build all tools: 

    make prepare
Separate commands for building or initializing individual benchmarking tools (LMbench, UnixBench, Postmark, and pgbench) are also available in the `Makefile`.

## Running Benchmarks
Run all benchmarks:

    make run
Separate commands for running individual benchmarks are also available in the `Makefile`.

