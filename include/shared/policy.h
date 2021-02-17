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
#ifndef __KERN_BPF_POLICY_H
#define __KERN_BPF_POLICY_H

/*!
 * @brief provenance capture policy defined by the user.
 *
 */
struct capture_policy {
	// Whether to record provenance of all kernel object.
	bool prov_all;
	// Whether nodes should be compressed into one if possible.
	bool should_compress_node;
	// Whether edges should be compressed into one if possible.
	bool should_compress_edge;
	// every time a relation is recorded the two end nodes will be recorded
	// again if set to true.
	bool should_duplicate;
};

#endif
