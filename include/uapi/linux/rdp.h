/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the RDP protocol.
 *
 * Version:	@(#)rdp.h	1.0.2	04/28/93
 *
 * Author:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _UAPI_LINUX_RDP_H
#define _UAPI_LINUX_RDP_H

#include <linux/types.h>

struct rdphdr {
	__be16	source;
	__be16	dest;
	__be16	len;
	__sum16	check;
};

/* RDP socket options */
#define RDP_CORK	1	/* Never send partially complete segments */
#define RDP_ENCAP	100	/* Set the socket to accept encapsulated packets */
#define RDP_NO_CHECK6_TX 101	/* Disable sending checksum for RDP6X */
#define RDP_NO_CHECK6_RX 102	/* Disable accpeting checksum for RDP6 */
#define RDP_SEGMENT	103	/* Set GSO segmentation size */
#define RDP_GRO		104	/* This socket can receive RDP GRO packets */

/* RDP encapsulation types */
#define RDP_ENCAP_ESPINRDP_NON_IKE	1 /* draft-ietf-ipsec-nat-t-ike-00/01 */
#define RDP_ENCAP_ESPINRDP	2 /* draft-ietf-ipsec-rdp-encaps-06 */
#define RDP_ENCAP_L2TPINRDP	3 /* rfc2661 */
#define RDP_ENCAP_GTP0		4 /* GSM TS 09.60 */
#define RDP_ENCAP_GTP1U		5 /* 3GPP TS 29.060 */
#define RDP_ENCAP_RXRPC		6

#endif /* _UAPI_LINUX_RDP_H */
