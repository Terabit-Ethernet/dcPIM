#ifndef HEADER_H
#define HEADER_H

#include "debug.h"

#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
// RANKING
#define DATA 0
#define RTP_RTS 1
#define RTP_LISTSRCS 2
#define RTP_GOSRC 3
#define RTP_TOKEN 4 
#define RTP_ACK 5

#define MSS 1460

// ------- RTP -----
// RTP header format: ethernet | IPv4 header | ruf_hdr| (rts, gosrc, listsrc, token, data)
// If it is listsrc: listsrc | nrts_hdr (optional) | list of (src_addr, flow_size) pairs
struct ruf_hdr{
	uint8_t type;
};

struct ruf_rts_hdr {
	uint32_t flow_id;
	uint32_t flow_size;
	uint64_t start_time;
};

struct ruf_gosrc_hdr {
	uint32_t target_src_addr;
	uint32_t max_tokens;
};

struct ruf_listsrc_hdr {
	uint8_t has_nrts;
	uint32_t num_srcs; 
};

struct ruf_nrts_hdr {
	uint32_t nrts_src_addr;
	uint32_t nrts_dst_addr;
};

struct ruf_src_size_pair {
	uint32_t src_addr;
	uint32_t flow_size;
};

struct ruf_token_hdr {
	uint8_t priority;
	// uint8_t ttl;
	uint32_t flow_id;
	uint32_t round;
	uint32_t data_seq;
	uint32_t seq_num;
	uint32_t remaining_size;
}; 

struct ruf_data_hdr{
	uint8_t priority;
	uint32_t flow_id;
	uint32_t round;
	uint32_t data_seq;
	uint32_t seq_num;
};

struct ruf_ack_hdr {
	uint32_t flow_id;
};

void parse_header(struct rte_mbuf* p, struct ipv4_hdr** ipv4_hdr, struct ruf_hdr** ruf_hdr);
void add_ether_hdr(struct rte_mbuf* p);
void add_ip_hdr(struct rte_mbuf* p, struct ipv4_hdr* ipv4_hdr);
void add_ruf_hdr(struct rte_mbuf* p, struct ruf_hdr* ruf_hdr);
void add_ruf_rts_hdr(struct rte_mbuf *p, struct ruf_rts_hdr* ruf_rts_hdr);
void add_ruf_gosrc_hdr(struct rte_mbuf *p, struct ruf_gosrc_hdr* ruf_gosrc_hdr);
void add_ruf_listsrc_hdr(struct rte_mbuf *p, struct ruf_listsrc_hdr* ruf_listsrc_hdr);
void add_ruf_nrts_hdr(struct rte_mbuf *p, struct ruf_nrts_hdr* ruf_nrts_hdr);
void add_ruf_token_hdr(struct rte_mbuf *p, struct ruf_token_hdr* ruf_token_hdr);
void add_ruf_data_hdr(struct rte_mbuf *p, struct ruf_data_hdr* ruf_data_hdr);
void add_ruf_ack_hdr(struct rte_mbuf *p, struct ruf_ack_hdr* ruf_ack_hdr);

#endif

