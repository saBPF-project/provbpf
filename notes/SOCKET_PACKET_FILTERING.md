# Socket Packet Filtering Implementation Notes

## Step 1: Creating the BPF program
Create a BPF program in the `kern.c` file with an arbitrary section name. E.g.:
```
SEC("socket1")
int socket_sample_prog(struct __sk_buff *skb) {
    if (skb->pkt_type == PACKET_OUTGOING) {
        return 0;
    }

    return 0;
}
```

## Step 2: Attach the BPF program to a socket from userspace
1. Get the socket BPF program fd using `bpf_get_prog_fd_by_sec_name`
1. Get sock fd using `open_raw_sock(<if_name>);`
1. Use `setsockopt` to attach the BPF program to the sock
From [pubs.opengroup.org](https://pubs.opengroup.org/onlinepubs/009696799/functions/setsockopt.html)
```
The setsockopt() function shall set the option specified by the option_name argument, at the protocol level specified by the level argument, to the value pointed to by the option_value argument for the socket associated with the file descriptor specified by the socket argument.
```
