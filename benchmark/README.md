# Benchmark

## Setting Up Benchmarking Tools

### Installing Dependencies - Fedora 

    sudo dnf install phoronix-test-suite
    sudo dnf install postgresql-contrib
    sudo dnf install postgresql-server

### Creating a Database for pgbench
pgbench is a benchmark tool for PostgreSQL. So before we initialize pgbench, we need to create a PostgreSQL database. In the psql shell:

    CREATE DATABASE <dbname>;
    CREATE USER <username>; 
    GRANT <permissions> ON DATABASE <dbname> TO <username>;

### Building and Initializing
Build all tools: 

    make prepare
Separate commands for building or initializing individual benchmarking tools (LMbench, UnixBench, Postmark, and pgbench) are also available in the Makefile.

