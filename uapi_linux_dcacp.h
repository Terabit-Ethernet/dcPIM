/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the DCACP protocol.
 *
 * Version:	@(#)dcacp.h	1.0.2	04/28/93
 *
 * Author:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _UAPI_LINUX_DCACP_H
#define _UAPI_LINUX_DCACP_H

#include <linux/types.h>

#define DCACP_HEADER_MAX_SIZE 64

#define DCACP_MAX_MESSAGE_LENGTH 1000000
/**
 * enum dcacp_packet_type - Defines the possible types of DCACP packets.
 * 
 * See the xxx_header structs below for more information about each type.
 */
enum dcacp_packet_type {
	// For Phost
	DATA               = 20,
	TOKEN              = 21,
	NOTIFICATION	   = 22,
	ACK  			   = 23,
	//For PIM
	RTS                = 24,
	GRANT			   = 25,
	ACCEPT			   = 26,

	BOGUS              = 27,      /* Used only in unit tests. */
	/* If you add a new type here, you must also do the following:
	 * 1. Change BOGUS so it is the highest opcode
	 * 2. Add support for the new opcode in homa_print_packet,
	 *    homa_print_packet_short, homa_symbol_for_type, and mock_skb_new.q
	 */
};

struct dcacphdr {
	__be16	source;
	__be16	dest;
	/**
	 * @unused1: corresponds to the sequence number field in TCP headers;
	 * must not be used by DCACP, in case it gets incremented during TCP
	 * offload.
	 */
	__be32 seq;
	
	__be32 unused2;

	/**
	 * @doff: High order 4 bits holds the number of 4-byte chunks in a
	 * data_header (low-order bits unused). Used only for DATA packets;
	 * must be in the same position as the data offset in a TCP header.
	 */
	__u8 doff;

	/** @type: One of the values of &enum packet_type. */
	__u8 type;

	/**
	 * @gro_count: value on the wire is undefined. Used only by
	 * dcacp_offload.c (it counts the total number of packets aggregated
	 * into this packet, including the top-level packet). Unused for now
	 */
	__u16 gro_count;
	
	/**
	 * @checksum: not used by Homa, but must occupy the same bytes as
	 * the checksum in a TCP header (TSO may modify this?).*/
	__be16 check;

	__be16 len;
	// *
	//  * @priority: the priority at which the packet was set; used
	//  * only for debugging.
	 
	// __u16 priority;
}__attribute__((packed));

/** 
 * struct data_segment - Wire format for a chunk of data that is part of
 * a DATA packet. A single sk_buff can hold multiple data_segments in order
 * to enable send and receive offload (the idea is to carry many network
 * packets of info in a single traversal of the Linux networking stack).
 * A DATA sk_buff contains a data_header followed by any number of
 * data_segments.
 */
struct data_segment {
	/**
	 * @offset: Offset within message of the first byte of data in
	 * this segment. Segments within an sk_buff are not guaranteed
	 * to be in order.
	 */
	__be32 offset;
	
	/** @segment_length: Number of bytes of data in this segment. */
	__be32 segment_length;
	
	/** @data: the payload of this segment. */
	char data[0];
} __attribute__((packed));

struct dcacp_data_hdr {
	struct dcacphdr common;
	// __u8 free_token;
	// __u8 priority;
	__be64 message_id;
	/* token seq number */
	// __be32 seq_no;
	// __be32 data_seq_no;
    struct data_segment seg;
} __attribute__((packed));

// _Static_assert(sizeof(struct dcacp_data_hdr) <= DCACP_HEADER_MAX_SIZE,
// 		"data_header too large");

// _Static_assert(((sizeof(struct dcacp_data_hdr) - sizeof(struct data_segment))
// 		& 0x3) == 0,
// 		" data_header length not a multiple of 4 bytes (required "
// 		"for TCP/TSO compatibility");

struct dcacp_token_hdr {
	struct dcacphdr common;
	__u8 free_token;
	__u8 priority;
	__be64 message_id;
	/* token seq number */
	__be32 seq_no;
	__be32 data_seq_no;
	__be32 remaining_size;
};

// _Static_assert(sizeof(struct dcacp_token_hdr) <= DCACP_HEADER_MAX_SIZE,
// 		"token_header too large");

struct dcacp_flow_sync_hdr {
	struct dcacphdr common;
	__be64 flow_id;
	__be64 flow_size;
	__be64 start_time;
};
// _Static_assert(sizeof(struct dcacp_flow_sync_hdr) <= DCACP_HEADER_MAX_SIZE,
// 		"flow_sync_header too large");

struct dcacp_ack_hdr {
	struct dcacphdr common;
	__be32 message_id;
};
// _Static_assert(sizeof(struct dcacp_ack_hdr) <= DCACP_HEADER_MAX_SIZE,
// 		"dcacp_ack_header too large");
struct dcacp_rts_hdr {
	struct dcacphdr common;
	__u8 iter;
	__be64 epoch;
	__be32 remaining_sz;
};

struct dcacp_grant_hdr {
	struct dcacphdr common;
	__u8 iter;
	__be64 epoch;
	__be32 remaining_sz;
	__u8 prompt;
};

struct dcacp_accept_hdr {
	struct dcacphdr common;
	__u8 iter;
	__be64 epoch;
	// __u8 accept;

};

enum {
	SKB_GSO_DCACP = 1 << 16,
	SKB_GSO_DCACP_L4 = 1 << 17,
};

#define SOL_DCACP 18
// #define SOL_DCACPLITE 19

/* DCACP's protocol number within the IP protocol space (this is not an
 * officially allocated slot).
 */
#define IPPROTO_DCACP 18
// #define IPPROTO_DCACPLITE 19

/* DCACP socket options */
#define DCACP_CORK	1	/* Never send partially complete segments */
#define DCACP_ENCAP	100	/* Set the socket to accept encapsulated packets */
#define DCACP_NO_CHECK6_TX 101	/* Disable sending checksum for DCACP6X */
#define DCACP_NO_CHECK6_RX 102	/* Disable accpeting checksum for DCACP6 */
#define DCACP_SEGMENT	103	/* Set GSO segmentation size */
#define DCACP_GRO		104	/* This socket can receive DCACP GRO packets */

/* DCACP encapsulation types */
#define DCACP_ENCAP_ESPINDCACP_NON_IKE	1 /* draft-ietf-ipsec-nat-t-ike-00/01 */
#define DCACP_ENCAP_ESPINDCACP	2 /* draft-ietf-ipsec-dcacp-encaps-06 */
#define DCACP_ENCAP_L2TPINDCACP	3 /* rfc2661 */
#define DCACP_ENCAP_GTP0		4 /* GSM TS 09.60 */
#define DCACP_ENCAP_GTP1U		5 /* 3GPP TS 29.060 */
#define DCACP_ENCAP_RXRPC		6
#define TCP_ENCAP_ESPINTCP	7 /* Yikes, this is really xfrm encap types. */

#endif /* _UAPI_LINUX_DCACP_H */
