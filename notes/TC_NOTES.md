# Implementing Egress Packet Provenance Capture Using tc-bpf

*Note:* Similar issue as `iproute2`, the `tc` tool issues the following **warning**
if the BPF kernel program has been compiled using BTF enabled:

```
[vagrant@localhost camflow-bpf]$ make run
rm -rf audit.log
sudo provbpfd
libbpf: elf: skipping unrecognized data section(14) .eh_frame
libbpf: elf: skipping relo section(15) .rel.eh_frame for section(14) .eh_frame

BTF debug data section '.BTF' rejected: Invalid argument (22)!
 - Length:       1285
Verifier analysis:

magic: 0xeb9f
version: 1
flags: 0x0
hdr_len: 24
type_off: 0
type_len: 752
str_off: 752
str_len: 509
btf_total_size: 1285
[1] PTR (anon) type_id=2
[2] STRUCT __sk_buff size=184 vlen=32
        len type_id=3 bits_offset=0
        pkt_type type_id=3 bits_offset=32
        mark type_id=3 bits_offset=64
        queue_mapping type_id=3 bits_offset=96
        protocol type_id=3 bits_offset=128
        vlan_present type_id=3 bits_offset=160
        vlan_tci type_id=3 bits_offset=192
        vlan_proto type_id=3 bits_offset=224
        priority type_id=3 bits_offset=256
        ingress_ifindex type_id=3 bits_offset=288
        ifindex type_id=3 bits_offset=320
        tc_index type_id=3 bits_offset=352
        cb type_id=5 bits_offset=384
        hash type_id=3 bits_offset=544
        tc_classid type_id=3 bits_offset=576
        data type_id=3 bits_offset=608
        data_end type_id=3 bits_offset=640
        napi_id type_id=3 bits_offset=672
        family type_id=3 bits_offset=704
        remote_ip4 type_id=3 bits_offset=736
        local_ip4 type_id=3 bits_offset=768
        remote_ip6 type_id=7 bits_offset=800
        local_ip6 type_id=7 bits_offset=928
        remote_port type_id=3 bits_offset=1056
        local_port type_id=3 bits_offset=1088
        data_meta type_id=3 bits_offset=1120
        (anon) type_id=8 bits_offset=1152
        tstamp type_id=10 bits_offset=1216
        wire_len type_id=3 bits_offset=1280
        gso_segs type_id=3 bits_offset=1312
        (anon) type_id=12 bits_offset=1344
        gso_size type_id=3 bits_offset=1408
[3] TYPEDEF __u32 type_id=4
[4] INT unsigned int size=4 bits_offset=0 nr_bits=32 encoding=(none)
[5] ARRAY (anon) type_id=3 index_type_id=6 nr_elems=5
[6] INT __ARRAY_SIZE_TYPE__ size=4 bits_offset=0 nr_bits=32 encoding=(none)
[7] ARRAY (anon) type_id=3 index_type_id=6 nr_elems=4
[8] UNION (anon) size=8 vlen=1
        flow_keys type_id=9 bits_offset=0
[9] PTR (anon) type_id=21
[10] TYPEDEF __u64 type_id=11
[11] INT long long unsigned int size=8 bits_offset=0 nr_bits=64 encoding=(none)
[12] UNION (anon) size=8 vlen=1
        sk type_id=13 bits_offset=0
[13] PTR (anon) type_id=22
[14] FUNC_PROTO (anon) return=15 args=(1 skb)
[15] INT int size=4 bits_offset=0 nr_bits=32 encoding=SIGNED
[16] FUNC tc_egress type_id=14
[17] INT char size=1 bits_offset=0 nr_bits=8 encoding=SIGNED
[18] ARRAY (anon) type_id=17 index_type_id=6 nr_elems=4
[19] VAR _license type_id=18 linkage=1
[20] DATASEC license size=0 vlen=1 size == 0
```

## Issue

Issuing the following command results in an error on the `provbpf` kernel:
```
[vagrant@localhost camflow-bpf]$ sudo tc filter add dev eth0 egress bpf da obj provbpf.o sec classifier
Error: TC classifier not found.
We have an error talking to the kernel
```
There are no issues on a mainline kernel version (i.e. `5.11.8-200.fc33.x86_64`)

## Kernelspace BPF program

Example program

```
#ifndef PROV_FILTER_EGRESS_OFF
SEC("classifier")
int cls_main(struct __sk_buff *skb) {
    return 0;
}
#endif
```

*Note:* section name needs to be compatible with tc-bpf or the following error
will be returned when running `make run`:

```
[vagrant@localhost camflow-bpf]$ make run
rm -rf audit.log
sudo provbpfd
libbpf: elf: skipping unrecognized data section(5) .eh_frame
libbpf: elf: skipping relo section(6) .rel.eh_frame for section(5) .eh_frame
libbpf: prog 'cls_main': missing BPF prog type, check ELF section name 'egress'
libbpf: failed to load program 'cls_main'
libbpf: failed to load object 'provbpf'
libbpf: failed to load BPF skeleton 'provbpf': -22
```

## Userspace
### Attaching the filter manually
1. Step 1: `tc qdisc add dev eth0 clsact` (enable ingress/egress filter
    configuration on network device `eth0`)
1. Step 2: `sudo tc filter add dev eth0 egress bpf da obj provbpf.o sec classifier`
    (attach BPF program corresponding to section `classifier` to egress filters
    on device `eth0`)
1. Step 3: `tc filter show dev eth0 egress` (check attached tc egress filters on `eth0`)
1. Step 4: `sudo tc filter del dev eth0 egress` (remove egress filter on `eth0`)

### Attaching the filter programatically
The classifier BPF program has been developed on the mainline kernel version `5.11.8`.
