// Project Calico BPF dataplane programs.
// Copyright (c) 2024 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_CT_CLEAN_H__
#define __CALI_CT_CLEAN_H__

#include "bpf.h"
#include "types.h"
#include "counters.h"
#include "conntrack.h"
#include "conntrack_types.h"

// sub_age calculates now-then assuming that the difference is less than
// 1<<63.  Values larger than that are assumed to have wrapped (then>now) and
// 0 is returned in that case.
static __u64 sub_age(__u64 now, __u64 then)
{
	__u64 age = now - then;
	if (age > (1ull<<63)) {
		// Wrapped, assume that means then > now.
		return 0;
	}
	return age;
}

#define CT_VALUE_FINS_SEEN_DSR(value) (value->a_to_b.fin_seen || value->b_to_a.fin_seen)
#define CT_VALUE_FINS_SEEN_NON_DSR(value) (value->a_to_b.fin_seen && value->b_to_a.fin_seen)
#define CT_VALUE_ESTABLISHED(value) (value->a_to_b.syn_seen && value->a_to_b.ack_seen && value->b_to_a.syn_seen && value->b_to_a.ack_seen)
#define CT_VALUE_DSR(value) (value->flags & CALI_CT_FLAG_DSR_FWD)

// max_age returns the maximum age for the given conntrack "tracking" entry.
static __u64 calculate_max_age(const struct calico_ct_key *key, const struct calico_ct_value *value)
{
	__u64 max_age;
	switch (key->protocol) {
	case IPPROTO_TCP:
		if (value->a_to_b.rst_seen || value->b_to_a.rst_seen) {
			max_age = __ct_globals.tcp_reset_seen;
		} else if (
		    (CT_VALUE_DSR(value) && CT_VALUE_FINS_SEEN_DSR(value)) ||
		    CT_VALUE_FINS_SEEN_NON_DSR(value)
		) {
			max_age = __ct_globals.tcp_fins_seen;
		} else if (CT_VALUE_ESTABLISHED(value) || CT_VALUE_DSR(value)) {
			if (value->rst_seen) {
				/* We have seen RST in the past, but we have seen traffic
				 * since then so we want to be cautious and not tear down
				 * the conntrack too soon in case the RST was spurious,
				 * but we are also not sure if the connection is still
				 * established.
				 */
				max_age = __ct_globals.tcp_fins_seen;
			} else {
				max_age = __ct_globals.tcp_established;
			}
		} else {
			max_age = __ct_globals.tcp_syn_sent;
		}
		break;
	case IPPROTO_UDP:
		max_age = __ct_globals.udp_timeout;
		break;
	case IPPROTO_ICMP_46:
		max_age = __ct_globals.icmp_timeout;
		break;
	default:
		max_age = __ct_globals.generic_timeout;
		break;
	}
	return max_age;
}

static CALI_BPF_INLINE bool entry_expired(const struct calico_ct_key *key, const struct calico_ct_value *value)
{
	__u64 now = bpf_ktime_get_ns();
	__u64 age = sub_age(now, value->last_seen);
	__u64 max_age = calculate_max_age(key, value);
	return age > max_age;
}

#endif // __CALI_CT_CLEAN_H__
