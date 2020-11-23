# Benchmark

## Setting Up Benchmarking Tools

### Installing Dependencies - Fedora 

    sudo dnf install phoronix-test-suite
    sudo dnf install postgresql-contrib
    sudo dnf install postgresql-server

### Creating a Database for pgbench
pgbench is a benchmark tool for PostgreSQL. So before we initialize pgbench, we need to create a PostgreSQL database. In the `psql shell`:

    CREATE DATABASE <dbname>;
    CREATE USER <username>; 
    GRANT <permissions> ON DATABASE <dbname> TO <username>;

### Building and Initializing
Build all tools: 

    make prepare
Separate commands for building or initializing individual benchmarking tools (LMbench, UnixBench, Postmark, and pgbench) are also available in the `Makefile`.

## Running Benchmarks
Run all benchmarks:

    make run
Separate commands for running individual benchmarks are also available in the `Makefile`.

### LMbench - Fedora 28 and above
Since [Fedora 28](https://fedoraproject.org/wiki/Releases/28/ChangeSet#Removal_of_Sun_RPC_Interfaces_From_glibc), the Sun RPC interfaces have been removed from glibc. As a result, the compilation of LMbench returns an error because it is still reliant on the Sun RPC support. To solve this problem, add the following lines to `script/build`:

    LDLIBS="${LDLIBS} -ltirpc"
    CFLAGS="${CFLAGS} -I/usr/include/tirpc"
And add `libtirpc-devel`:

    sudo dnf install libtirpc-devel

### UnixBench
Installing dependencies in Fedora:

    sudo dnf install perl-Time-HiRes
