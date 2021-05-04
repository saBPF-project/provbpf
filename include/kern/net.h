/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020-2021 Harvard University
 * Copyright (C) 2020-2021 University of Bristol
 *
 * Author: Thomas Pasquier <thomas.pasquier@bristol.ac.uk>
 * Author: Bogdan Stelea <bs17580@bristol.ac.uk>
 * Author: Soo Yee Lim <sooyee.lim@bristol.ac.uk>
 * Author: Xueyuan "Michael" Han <hanx@g.harvard.edu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 */
#ifndef __KERN_BPF_PROVENANCE_NET_H
#define __KERN_BPF_PROVENANCE_NET_H

#include <bpf/bpf_endian.h>

/*!
 * @brief Record the address provenance node that binds to the socket node.
 *
 * This function creates a long provenance entry node ENT_ADDR that binds to the
 * socket provenance entry @prov.
 * Record provenance relation RL_NAMED by calling "record_relation" function.
 * Relation will not be recorded, if:
 * 1. The socket inode is not recorded or the name (addr) of the socket has been
 * recorded already, or
 * 2. Failure occurs.
 * The information in the ENT_ADDR node is filled in from @address and @addrlen.
 * This provenance node is short-lived and thus we free the memory once we have
 * recorded the relation.
 * @param address The address of the socket.
 * @param addrlen The length of the addres.
 * @param prov The provenance entry pointer of the socket.
 * @return 0 if no error occurred; -ENOMEM if no memory can be allocated for the
 * new long provenance node ENT_ADDR; Other error codes inherited from
 * record_relation function.
 *
 */
#define AF_UNIX 1
#define AF_INET 2
#define AF_INET6 10

#define PF_INET		AF_INET

#define IP_OFFSET	0x1FFF		/* "Fragment Offset" part	*/

static __always_inline void record_address(struct sockaddr *address, int addrlen, union prov_elt *prov) {
	int map_id = ADDRESS_PERCPU_LONG_TMP;
	union long_prov_elt *aprov = bpf_map_lookup_elem(&long_tmp_prov_map, &map_id);
	if (!aprov)
		return;

	prov_init_node((union prov_elt *)aprov, ENT_ADDR);

    // copy each type of address
    // TODO expand to more types
	if (address->sa_family == AF_INET)
        bpf_probe_read_kernel(aprov->address_info.addr, sizeof(struct sockaddr_in), address);
    else if (address->sa_family == AF_INET)
        bpf_probe_read_kernel(aprov->address_info.addr, sizeof(struct sockaddr_in6), address);
    else if (address->sa_family == AF_UNIX)
        bpf_probe_read_kernel(aprov->address_info.addr, sizeof(struct sockaddr_un), address);
    else
        bpf_probe_read_kernel(aprov->address_info.addr, sizeof(struct sockaddr), address);

    __record_relation_ls(RL_ADDRESSED, aprov, prov, NULL, 0);
}

static __always_inline unsigned int skb_headlen(struct sk_buff *skb)
{
	return skb->len - skb->data_len;
}

static __always_inline unsigned char *skb_network_header(struct sk_buff *skb)
{
	return skb->head + skb->network_header;
}

static __always_inline int skb_network_offset(struct sk_buff *skb)
{
	return skb_network_header(skb) - skb->data;
}

static __always_inline void *__skb_header_pointer(struct sk_buff *skb, int offset,
		     int len, void *data, int hlen, void *buffer)
{
	if (hlen - offset >= len)
		return data + offset;

	return buffer;
}

static __always_inline void *skb_header_pointer(struct sk_buff *skb, int offset, int len, void *buffer)
{
	return __skb_header_pointer(skb, offset, len, skb->data,
				    skb_headlen(skb), buffer);
}

static __always_inline void __extract_tcp_info(struct sk_buff *skb,
					       struct iphdr *ih,
						   uint8_t ihl,
					       int offset,
					       union prov_elt *pprov) {
  struct tcphdr _tcph;
 	struct tcphdr *th;
 	int tcpoff;
	uint16_t frag_off = _(ih->frag_off);

	if (bpf_ntohs(frag_off) & IP_OFFSET)
		return;

	tcpoff = offset + ihl * 4;    // Point to tcp packet.
	th = skb_header_pointer(skb, tcpoff, sizeof(_tcph), &_tcph);
	if (!th)
		return;

	packet_identifier(pprov).snd_port = _(th->source);
	packet_identifier(pprov).rcv_port = _(th->dest);
	packet_identifier(pprov).seq = _(th->seq);
}

static __always_inline void __extract_udp_info(struct sk_buff *skb,
					       struct iphdr *ih,
						   uint8_t ihl,
					       int offset,
					       union prov_elt *pprov) {
  struct udphdr _udph;
 	struct udphdr *uh;
 	int udpoff;
	uint16_t frag_off = _(ih->frag_off);

	if (bpf_ntohs(frag_off) & IP_OFFSET)
		return;

	udpoff = offset + ihl * 4;    // Point to tcp packet.
	uh = skb_header_pointer(skb, udpoff, sizeof(_udph), &_udph);
	if (!uh)
		return;

	packet_identifier(pprov).snd_port = _(uh->source);
	packet_identifier(pprov).rcv_port = _(uh->dest);
}

static __always_inline void init_ipv4_prov(union prov_elt *pprov, struct sk_buff *skb) {
	int offset;
	struct iphdr _iph, *ih;
	uint8_t ihl = 0;

	__builtin_memset(pprov, 0, sizeof(union prov_elt));
	prov_init_node(pprov, ENT_PACKET);

	offset = skb_network_offset(skb);
	ih = skb_header_pointer(skb, offset, sizeof(_iph), &_iph);
	if (!ih)
		return;

	bpf_probe_read(&ihl, 1, ih);

#if defined(__LITTLE_ENDIAN_BITFIELD)
	ihl = ihl >> 4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	ihl = ihl & 0x0F;
#endif

	// Collect IP element of prov identifier.
	// force parse endian casting
	packet_identifier(pprov).id = _(ih->id);
	packet_identifier(pprov).snd_ip = _(ih->saddr);
	packet_identifier(pprov).rcv_ip = _(ih->daddr);
	packet_identifier(pprov).protocol = _(ih->protocol);
	packet_info(pprov).len = _(ih->tot_len);

	switch (packet_identifier(pprov).protocol) {
		case IPPROTO_TCP:
			__extract_tcp_info(skb, ih, ihl,
					   offset, pprov);
			break;
		case IPPROTO_UDP:
			__extract_udp_info(skb, ih, ihl,
					   offset, pprov);
			break;
		default:
			break;
	}
}

#endif
