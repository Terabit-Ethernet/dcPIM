/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the DCPIM protocol.
 *
 * Version:	@(#)dcpim.h	1.0.2	04/28/93
 *
 * Author:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _UAPI_LINUX_DCPIM_H
#define _UAPI_LINUX_DCPIM_H

#include <linux/types.h>

/* include all headers not just DCPIM */
#define DCPIM_HEADER_MAX_SIZE 128 +  MAX_HEADER

#define DCPIM_MAX_MESSAGE_LENGTH 1000000
/**
 * enum dcpim_packet_type - Defines the possible types of DCPIM packets.
 * 
 * See the xxx_header structs below for more information about each type.
 */
enum dcpim_packet_type {
	// For Phost
	DATA               = 20,
	TOKEN              = 21,
	NOTIFICATION	   = 22,
	ACK  			   = 23,
	//For PIM
	RTS                = 24,
	GRANT			   = 25,
	ACCEPT			   = 26,

	FIN                = 27,
	SYN_ACK		 	   = 28,
	FIN_ACK		       = 29,
	NOTIFICATION_MSG   = 30,
	DATA_MSG		   = 31,
	FIN_MSG			   = 32,
	FIN_ACK_MSG		   = 33,
};

struct dcpimhdr {
	__be16	source;
	__be16	dest;
	/**
	 * @unused1: corresponds to the sequence number field in TCP headers;
	 * must not be used by DCPIM, in case it gets incremented during TCP
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
	 * dcpim_offload.c (it counts the total number of packets aggregated
	 * into this packet, including the top-level packet). Unused for now
	 */
	__u16 gro_count;
	
	/**
	 * @checksum: not used by dcPIM, but must occupy the same bytes as
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

struct dcpim_data_hdr {
	struct dcpimhdr common;
	__u8 free_token;
	/* padding*/
	__u8 unused1;
	__u16 unused2;
	// __u8 priority;
	__be64 message_id;
	/* token seq number */
	// __be32 seq_no;
	// __be32 data_seq_no;
    struct data_segment seg;
} __attribute__((packed));

// _Static_assert(sizeof(struct dcpim_data_hdr) <= DCPIM_HEADER_MAX_SIZE,
// 		"data_header too large");

// _Static_assert(((sizeof(struct dcpim_data_hdr) - sizeof(struct data_segment))
// 		& 0x3) == 0,
// 		" data_header length not a multiple of 4 bytes (required "
// 		"for TCP/TSO compatibility");

struct dcpim_token_hdr {
	struct dcpimhdr common;
	__be32 rcv_nxt;
	__be32 token_nxt;
	__u8 priority;
	__u8 num_sacks;
	/* token seq number */
}__attribute__((packed));

// _Static_assert(sizeof(struct dcpim_token_hdr) <= DCPIM_HEADER_MAX_SIZE,
// 		"token_header too large");

struct dcpim_flow_sync_hdr {
	struct dcpimhdr common;
	__be64 message_id;
	/*UINT32_MAX refers to long flow; otherwise, the flow is the short flow. */
	__be32 message_size;
	__be64 start_time;
};

struct dcpim_syn_ack_hdr {
	struct dcpimhdr common;
	__be64 message_id;
	/*UINT32_MAX refers to long flow; otherwise, the flow is the short flow. */
	__be32 message_size;
	__be64 start_time;
};

struct dcpim_fin_ack_hdr {
	struct dcpimhdr common;
	__be64 message_id;
	/*UINT32_MAX refers to long flow; otherwise, the flow is the short flow. */
	// __be32 message_size;
	// __be64 start_time;
};

struct dcpim_fin_hdr {
	struct dcpimhdr common;
	__be64 message_id;
	/*UINT32_MAX refers to long flow; otherwise, the flow is the short flow. */
	// __be32 message_size;
	// __be64 start_time;
};

// _Static_assert(sizeof(struct dcpim_flow_sync_hdr) <= DCPIM_HEADER_MAX_SIZE,
// 		"flow_sync_header too large");

struct dcpim_ack_hdr {
	struct dcpimhdr common;
	__be32 rcv_nxt;
};
// _Static_assert(sizeof(struct dcpim_ack_hdr) <= DCPIM_HEADER_MAX_SIZE,
// 		"dcpim_ack_header too large");
struct dcpim_rts_hdr {
	struct dcpimhdr common;
	__u8 round;
	__be64 epoch;
	__be32 remaining_sz;
};

struct dcpim_grant_hdr {
	struct dcpimhdr common;
	__u8 round;
	__be64 epoch;
	__be32 remaining_sz;
	// __u8 prompt;
};

struct dcpim_accept_hdr {
	struct dcpimhdr common;
	__u8 round;
	__be64 epoch;
	__be32 remaining_sz;
	// __u8 accept;

};

enum {
	SKB_GSO_DCPIM = 1 << 19,
	SKB_GSO_DCPIM_L4 = 1 << 20,
};

#define SOL_DCPIM 0xFE
// #define SOL_DCPIMLITE 19

/* DCPIM's protocol number within the IP protocol space (this is not an
 * officially allocated slot).
 */
#define IPPROTO_DCPIM 0xFE
// #define IPPROTO_DCPIMLITE 19

/* DCPIM socket options */
#define DCPIM_CORK	1	/* Never send partially complete segments */
#define DCPIM_ENCAP	100	/* Set the socket to accept encapsulated packets */
#define DCPIM_NO_CHECK6_TX 101	/* Disable sending checksum for DCPIM6X */
#define DCPIM_NO_CHECK6_RX 102	/* Disable accpeting checksum for DCPIM6 */
#define DCPIM_SEGMENT	103	/* Set GSO segmentation size */
#define DCPIM_GRO		104	/* This socket can receive DCPIM GRO packets */

/* DCPIM encapsulation types */
#define DCPIM_ENCAP_ESPINDCPIM_NON_IKE	1 /* draft-ietf-ipsec-nat-t-ike-00/01 */
#define DCPIM_ENCAP_ESPINDCPIM	2 /* draft-ietf-ipsec-dcpim-encaps-06 */
#define DCPIM_ENCAP_L2TPINDCPIM	3 /* rfc2661 */
#define DCPIM_ENCAP_GTP0		4 /* GSM TS 09.60 */
#define DCPIM_ENCAP_GTP1U		5 /* 3GPP TS 29.060 */
#define DCPIM_ENCAP_RXRPC		6
#define TCP_ENCAP_ESPINTCP	7 /* Yikes, this is really xfrm encap types. */

#endif /* _UAPI_LINUX_DCPIM_H */
