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

#define ihlen(ih)    (ih->ihl * 4)
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
static __always_inline int record_address(struct sockaddr *address, int addrlen, union prov_elt *prov) {
	int map_id = ADDRESS_PERCPU_LONG_TMP;
	union long_prov_elt *ptr_prov_addr = bpf_map_lookup_elem(&long_tmp_prov_map, &map_id);
	if (!ptr_prov_addr) {
		return 0;
	}
	prov_init_node((union prov_elt *)ptr_prov_addr, ENT_ADDR);

	ptr_prov_addr->address_info.length = addrlen;
	__builtin_memcpy(&(ptr_prov_addr->address_info.addr), &address, sizeof(struct sockaddr_storage));

  record_relation(RL_ADDRESSED, ptr_prov_addr, true, prov, false, NULL, 0);

	return 0;
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

	if (!skb ||
	    bpf_skb_load_bytes(skb, offset, buffer, len) < 0)
		return 0;

	return buffer;
}

static __always_inline void *skb_header_pointer(struct sk_buff *skb, int offset, int len, void *buffer)
{
	return __skb_header_pointer(skb, offset, len, skb->data,
				    skb_headlen(skb), buffer);
}

static __always_inline void provenance_alloc_with_ipv4_skb(union prov_elt *ptr_prov_pck, struct sk_buff *skb) {
	int offset;
	struct iphdr _iph, *ih;

	offset = skb_network_offset(skb);
	ih = skb_header_pointer(skb, offset, sizeof(_iph), &_iph);
	if (!ih)
		return;

	if (ihlen(ih) < sizeof(_iph))
		return;

	// __builtin_memset(ptr_prov_pck, 0, sizeof(union prov_elt));
    // prov_init_node(ptr_prov_pck, ENT_PACKET);
	//
	// // Collect IP element of prov identifier.
	// // force parse endian casting
	// packet_identifier(ptr_prov_pck).id = (uint16_t)ih->id;
	// packet_identifier(ptr_prov_pck).snd_ip = (uint32_t)ih->saddr;
	// packet_identifier(ptr_prov_pck).rcv_ip = (uint32_t)ih->daddr;
	// packet_identifier(ptr_prov_pck).protocol = ih->protocol;
	// packet_info(ptr_prov_pck).len = (size_t)ih->tot_len;

	return;
}
#endif
