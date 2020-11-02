/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#ifndef __KERN_BPF_POLICY_H
#define __KERN_BPF_POLICY_H

/*!
 * @brief provenance capture policy defined by the user.
 *
 */
struct capture_policy {
	// Whether provenance capture is enabled.
	bool prov_enabled;
	// Whether to record provenance of all kernel object.
	bool prov_all;
	// Whether nodes should be compressed into one if possible.
	bool should_compress_node;
	// Whether edges should be compressed into one if possible.
	bool should_compress_edge;
	// every time a relation is recorded the two end nodes will be recorded
	// again if set to true.
	bool should_duplicate;
	// Node to be filtered out (i.e., not recorded).
	uint64_t prov_node_filter;
	// Node to be filtered out if it is part of propagate.
	uint64_t prov_propagate_node_filter;
	// Edge of category "derived" to be filtered out.
	uint64_t prov_derived_filter;
	// Edge of category "generated" to be filtered out.
	uint64_t prov_generated_filter;
	// Edge of category "used" to be filtered out.
	uint64_t prov_used_filter;
	// Edge of category "informed" to be filtered out.
	uint64_t prov_informed_filter;
	// Edge of category "derived" to be filtered out if it is part of
	// propagate.
	uint64_t prov_propagate_derived_filter;
	// Edge of category "generated" to be filtered out if it is part of
	// propagate.
	uint64_t prov_propagate_generated_filter;
	// Edge of category "used" to be filtered out if it is part of
	// propagate.
	uint64_t prov_propagate_used_filter;
	// Edge of category "informed" to be filtered out if it is part of
	// propagate.
	uint64_t prov_propagate_informed_filter;
};

#endif
