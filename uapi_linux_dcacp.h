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

	//For PIM
	RTS                = 23,
	GRANT			   = 24,
	ACCEPT			   = 25,

	BOGUS              = 26,      /* Used only in unit tests. */
	/* If you add a new type here, you must also do the following:
	 * 1. Change BOGUS so it is the highest opcode
	 * 2. Add support for the new opcode in homa_print_packet,
	 *    homa_print_packet_short, homa_symbol_for_type, and mock_skb_new.q
	 */
};

struct dcacphdr {
	__be16	source;
	__be16	dest;
	__be16	len;
	__sum16	check;
	__u8 type;
};
struct dcacp_data_hdr {
	struct dcacphdr common;
	__u8 free_token;
	__u8 priority;
	__u8 message_id;
	/* token seq number */
	__be32 seq_no;
	__be32 data_seq_no;
};

struct dcacp_token_hdr {
	struct dcacphdr common;
	__u8 free_token;
	__u8 priority;
	__be32 message_id;
	/* token seq number */
	__be32 seq_no;
	__be32 data_seq_no;
	__be32 remaining_size;
};

struct dcacp_flow_sync_hdr {
	struct dcacphdr common;
	__be32 message_id;
	__be32 message_size;
	__be64 start_time;
};

struct dcacp_ack_hdr {
	struct dcacphdr common;
	__be32 message_id;
};

enum {
	SKB_GSO_DCACP = 1 << 16,
	SKB_GSO_DCACP_L4 = 1 << 17,
};

#define SOL_DCACP 18
#define SOL_DCACPLITE 19

/* DCACP's protocol number within the IP protocol space (this is not an
 * officially allocated slot).
 */
#define IPPROTO_DCACP 18
#define IPPROTO_DCACPLITE 19

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
