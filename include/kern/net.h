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

static __always_inline int record_address(struct sockaddr *address, int addrlen, union prov_elt *prov) {
	int map_id = ADDRESS_PERCPU_LONG_TMP;
	union long_prov_elt *aprov = bpf_map_lookup_elem(&long_tmp_prov_map, &map_id);
	if (!aprov)
		return 0;

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

	return 0;
}

#endif
