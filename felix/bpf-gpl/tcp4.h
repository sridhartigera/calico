// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_TCP4_H__
#define __CALI_TCP4_H__

#include <linux/if_ether.h>
#include <linux/ip.h>

#include "bpf.h"
#include "log.h"
#include "skb.h"

static CALI_BPF_INLINE int tcp_v4_rst(struct cali_tc_ctx *ctx) {

        int ret;

        if (skb_refresh_validate_ptrs(ctx, TCP_SIZE)) {
                deny_reason(ctx, CALI_REASON_SHORT);
                CALI_DEBUG("TCP reset : too short");
                return -1;
        }
        struct iphdr ip_orig = *ip_hdr(ctx);
	struct tcphdr th_orig = *tcp_hdr(ctx);
	int original_len = ctx->skb->len;

	CALI_DEBUG("TCP reset origin len %d", original_len);
	CALI_DEBUG("TCP reset doff %d", th_orig.doff);
	CALI_DEBUG("TCP reset seq %u", bpf_ntohl(th_orig.seq));
	CALI_DEBUG("TCP reset ack_seq %u", bpf_ntohl(th_orig.ack_seq));
	CALI_DEBUG("TCP reset syn %d", th_orig.syn);
	CALI_DEBUG("TCP reset fin %d", th_orig.fin);


	/* Trim to minimum size */
	__u32 len = skb_iphdr_offset(ctx) + IP_SIZE + TCP_SIZE /* max IP len */;
        CALI_DEBUG("Trimming to %d", len);
        int err = bpf_skb_change_tail(ctx->skb, len,  0);
        if (err) {
                CALI_DEBUG("tcp reset reply: early bpf_skb_change_tail (len=%d) failed (err=%d)", len, err);
                return -1;
        }               

	CALI_DEBUG("TCP reset: resized to %d", ctx->skb->len);
#if 0
        /* make room for the new IP + ICMP header */
        int new_hdrs_len = sizeof(struct tcphdr);
        CALI_DEBUG("Inserting %d", new_hdrs_len);
        ret = bpf_skb_adjust_room(ctx->skb, new_hdrs_len, BPF_ADJ_ROOM_MAC, 0);
        if (ret) {
                CALI_DEBUG("ICMP v4 reply: failed to make room");
                return -1;
        }

        len += new_hdrs_len;
        CALI_DEBUG("Len after insert %d", len);
#endif

	/* Revalidate all pointers */
	if (skb_refresh_validate_ptrs(ctx, TCP_SIZE)) {
		deny_reason(ctx, CALI_REASON_SHORT);
		CALI_DEBUG("TCP reset : too short");
		return -1;
	}
	ip_hdr(ctx)->version = 4;
	ip_hdr(ctx)->ihl = 5;
	ip_hdr(ctx)->tos = 0;
	ip_hdr(ctx)->ttl = 64;
	ip_hdr(ctx)->protocol = IPPROTO_TCP;
	ip_hdr(ctx)->saddr = ip_orig.daddr;
	ip_hdr(ctx)->daddr = ip_orig.saddr;
	ip_hdr(ctx)->check = 0;
	ip_hdr(ctx)->tot_len = bpf_htons(len - (CALI_F_L3_DEV ? 0 : ETH_SIZE));
	ctx->ipheader_len = 20;

	CALI_DEBUG("TCP reset: src %d, dst %d", bpf_ntohs(th_orig.source), bpf_ntohs(th_orig.dest));

	struct tcphdr *th = ((void *)ip_hdr(ctx)) + IP_SIZE;
	th->source = th_orig.dest;
	th->dest = th_orig.source;
	th->rst = 1;
	th->doff = sizeof(struct tcphdr) / 4;
	th->seq = 0;

	if (th_orig.ack) {
		th->seq = th_orig.ack_seq;
	} else {
		th->ack_seq = bpf_htonl(bpf_ntohl(th_orig.seq) + th_orig.syn + th_orig.fin + 
				original_len - (th_orig.doff << 2));
		th->ack = 1;
	}
	th->check = 0;

	__wsum ip_csum = bpf_csum_diff(0, 0, ctx->ip_header, sizeof(struct iphdr), 0);
	__wsum tcp_csum = bpf_csum_diff(0, 0, (__u32 *)th, len - sizeof(struct iphdr) - skb_iphdr_offset(ctx), 0);
        ret = bpf_l3_csum_replace(ctx->skb,
                        skb_iphdr_offset(ctx) + offsetof(struct iphdr, check), 0, ip_csum, 0);
        if (ret) {
                CALI_DEBUG("ICMP v4 reply: set ip csum failed");
                return -1;
        }
	ret = bpf_l4_csum_replace(ctx->skb, sizeof(struct ethhdr) + sizeof(struct iphdr) +
			offsetof(struct tcphdr, check), 0, tcp_csum, 0);

	return 0;
}

#endif /* __CALI_TCP4_H__ */
