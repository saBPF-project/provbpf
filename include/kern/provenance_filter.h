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
#ifndef __KERN_BPF_PROVENANCE_FILTER_H
#define __KERN_BPF_PROVENANCE_FILTER_H

static __always_inline bool should_record_packet(union prov_elt *prov) {
    uint32_t policy_key = 0;
    struct capture_policy *prov_policy = bpf_map_lookup_elem(&policy_map, &policy_key);

    if (prov_policy && prov_policy->prov_all)
        return true;
    if (provenance_is_tracked(prov))
        return true;
    return false;
}

#endif
