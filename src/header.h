#ifndef HEADER_H
#define HEADER_H

#include "debug.h"

#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
// RANKING
#define DATA 0
#define PIM_RTS 1
#define PIM_LISTSRCS 2
#define PIM_GOSRC 3
#define PIM_TOKEN 4 
#define PIM_ACK 5

#define MSS 1460

// ------- PIM -----
// PIM header format: ethernet | IPv4 header | pim_hdr| (rts, gosrc, listsrc, token, data)
// If it is listsrc: listsrc | nrts_hdr (optional) | list of (src_addr, flow_size) pairs
struct pim_hdr{
	uint8_t type;
};

struct pim_rts_hdr {
	uint32_t flow_id;
	uint32_t flow_size;
	uint64_t start_time;
};

struct pim_gosrc_hdr {
	uint32_t target_src_addr;
	uint32_t max_tokens;
};

struct pim_listsrc_hdr {
	uint8_t has_nrts;
	uint32_t num_srcs; 
};

struct pim_nrts_hdr {
	uint32_t nrts_src_addr;
	uint32_t nrts_dst_addr;
};

struct pim_src_size_pair {
	uint32_t src_addr;
	uint32_t flow_size;
};

struct pim_token_hdr {
	uint8_t priority;
	// uint8_t ttl;
	uint32_t flow_id;
	uint32_t round;
	uint32_t data_seq;
	uint32_t seq_num;
	uint32_t remaining_size;
}; 

struct pim_data_hdr{
	uint8_t priority;
	uint32_t flow_id;
	uint32_t round;
	uint32_t data_seq;
	uint32_t seq_num;
};

struct pim_ack_hdr {
	uint32_t flow_id;
};

void parse_header(struct rte_mbuf* p, struct ipv4_hdr** ipv4_hdr, struct pim_hdr** pim_hdr);
void add_ether_hdr(struct rte_mbuf* p);
void add_ip_hdr(struct rte_mbuf* p, struct ipv4_hdr* ipv4_hdr);
void add_pim_hdr(struct rte_mbuf* p, struct pim_hdr* pim_hdr);
void add_pim_rts_hdr(struct rte_mbuf *p, struct pim_rts_hdr* pim_rts_hdr);
void add_pim_gosrc_hdr(struct rte_mbuf *p, struct pim_gosrc_hdr* pim_gosrc_hdr);
void add_pim_listsrc_hdr(struct rte_mbuf *p, struct pim_listsrc_hdr* pim_listsrc_hdr);
void add_pim_nrts_hdr(struct rte_mbuf *p, struct pim_nrts_hdr* pim_nrts_hdr);
void add_pim_token_hdr(struct rte_mbuf *p, struct pim_token_hdr* pim_token_hdr);
void add_pim_data_hdr(struct rte_mbuf *p, struct pim_data_hdr* pim_data_hdr);
void add_pim_ack_hdr(struct rte_mbuf *p, struct pim_ack_hdr* pim_ack_hdr);

#endif

