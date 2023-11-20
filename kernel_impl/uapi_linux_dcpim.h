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
	DATA               = 0x20,
	TOKEN             ,
	RTX_TOKEN		  ,
	NOTIFICATION_LONG ,
	NOTIFICATION_SHORT ,
	ACK  			  ,
	//For PIM
	RTS               ,
	GRANT			  , 
	ACCEPT			  ,

	FIN               , 
	SYN_ACK		 	  ,
	FIN_ACK		      , 
	/* per-msg granularity for short messages */
	NOTIFICATION_MSG  , 
	DATA_MSG		  , 
	FIN_MSG			  , 
	FIN_ACK_MSG		  , 
	RTX_MSG 		  ,
	RESYNC_MSG        ,
};

struct dcpimhdr {
	__be16	source;
	__be16	dest;
	/**
	 * @seq: corresponds to the sequence number field in TCP headers;
	 * must not be used by DCPIM, in case it gets incremented during TCP
	 * offload.
	 */
	__be32 seq;
	
	__be32 ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	res1:4,
		doff:4,
		fin:1,
		syn:1,
		rst:1,
		psh:1,
		ack:1,
		urg:1,
		ece:1,
		cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	doff:4,
		res1:4,
		cwr:1,
		ece:1,
		urg:1,
		ack:1,
		psh:1,
		rst:1,
		syn:1,
		fin:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
	/** @type: One of the values of &enum packet_type. */
	__u8 type;
	__u8 unused4;
	/**
	* @check: not used by dcPIM, but must occupy the same bytes as
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
	__be64 message_id;
	__be32 message_size;
	__u8 flow_sync;
	/* padding*/
	__u8 unused1;
	__u16 unused2;
	// __u8 priority;
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
};

struct dcpim_syn_ack_hdr {
	struct dcpimhdr common;
	__be64 message_id;
	/*UINT32_MAX refers to long flow; otherwise, the flow is the short flow. */
	__be32 message_size;
};

struct dcpim_fin_ack_hdr {
	struct dcpimhdr common;
	__be64 message_id;
	/*UINT32_MAX refers to long flow; otherwise, the flow is the short flow. */
	__be32 message_size;
};

struct dcpim_fin_hdr {
	struct dcpimhdr common;
	__be64 message_id;
	/*UINT32_MAX refers to long flow; otherwise, the flow is the short flow. */
	union {
	__be32 message_size;
	__be32 num_msgs;
	};
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
	__u8 rtx_channel;
	__u8 prompt_channel;
	__u16 source;
	__u16 dest;
	__be64 epoch;
	__be32 remaining_sz;
};

struct dcpim_grant_hdr {
	struct dcpimhdr common;
	__u8 round;
	__u8 rtx_channel;
	__u8 prompt_channel;
	/* src port of socket to match */
	__u16 source;
	/* dst port of socket to match */
	__u16 dest;
	__be64 epoch;
	__be32 remaining_sz;
	// __u8 prompt;
};

struct dcpim_accept_hdr {
	struct dcpimhdr common;
	__u8 round;
	__u8 rtx_channel;
	__u8 prompt_channel;
	__u16 source;
	__u16 dest;
	__be64 epoch;
	__be32 remaining_sz;
	// __u8 accept;

};

struct dcpim_rtx_msg_hdr {
	struct dcpimhdr common;
	__u8 round;
	__u8 rtx_channel;
	__u8 prompt_channel;
	__u16 source;
	__u16 dest;
	__be64 epoch;
	__be32 remaining_sz;
	// __u8 accept;
};

struct dcpim_resync_msg_hdr {
	struct dcpimhdr common;
	__be64 message_id;
	/*UINT32_MAX refers to long flow; otherwise, the flow is the short flow. */
	__be32 message_size;
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
#endif /* _UAPI_LINUX_DCPIM_H */
