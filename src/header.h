#ifndef HEADER_H
#define HEADER_H

#include "debug.h"
#include "config.h"
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
// PIM
#define DATA 0
#define PIM_FLOW_SYNC 1
#define PIM_RTS 2
#define PIM_GRANT 3
#define PIM_GRANTR 4
#define PIM_ACCEPT 5 
#define PIM_FIN 6
#define PIM_START 7
#define PIM_TOKEN 8
#define PIM_FLOW_SYNC_ACK 9
// #define PIM_FIN_SYNC_ACK 10
#define PIM_FIN_ACK 10
#define MSS 1460

// ------- PIM -----
// PIM header format: ethernet | IPv4 header | pim_hdr| (rts, gosrc, listsrc, token, data)
// If it is listsrc: listsrc | nrts_hdr (optional) | list of (src_addr, flow_size) pairs
struct pim_hdr{
	uint8_t type;
};

struct pim_flow_sync_hdr {
	uint32_t flow_id;
	uint32_t flow_size;
	uint64_t start_time;
};

struct pim_flow_sync_ack_hdr {
        uint32_t flow_id;
        //uint32_t flow_size;
        //uint64_t start_time;
};

struct pim_rts_hdr {
	uint32_t epoch;
	uint8_t iter;
	uint32_t remaining_sz;
};

struct pim_grant_hdr {
	uint32_t epoch;
	uint8_t iter;
	uint32_t remaining_sz;
	uint8_t prompt;
};

struct pim_grantr_hdr {
	uint32_t epoch;
	uint8_t iter;
};

struct pim_accept_hdr {
	uint32_t epoch;
	uint8_t iter;
	uint8_t accept;

};

struct pim_fin_hdr {
	uint32_t flow_id;
	uint32_t rd_ctrl_times;
};

struct pim_fin_ack_hdr {
        uint32_t flow_id;
 //       uint32_t rd_ctrl_times;
};
struct pim_data_hdr{
	uint8_t free_token;
	uint8_t priority;
	uint32_t flow_id;
	uint32_t seq_no;
	uint32_t data_seq_no;

};

struct pim_token_hdr{
	uint8_t free_token;
	uint8_t priority;
	uint32_t flow_id;
	uint32_t seq_no;
	uint32_t data_seq_no;
	uint32_t remaining_size;
};

void parse_header(struct rte_mbuf* p, struct ipv4_hdr** ipv4_hdr, struct pim_hdr** pim_hdr);
void add_ether_hdr(struct rte_mbuf* p, struct ether_addr* dst);
// void add_ip_hdr(struct rte_mbuf* p, struct ipv4_hdr* ipv4_hdr);
// void add_pim_hdr(struct rte_mbuf* p, struct pim_hdr* pim_hdr);
// void add_pim_rts_hdr(struct rte_mbuf *p, struct pim_rts_hdr* pim_rts_hdr);
// void add_pim_grant_hdr(struct rte_mbuf *p, struct pim_grant_hdr* pim_grant_hdr);
// void add_pim_grantr_hdr(struct rte_mbuf *p, struct pim_grantr_hdr* pim_grantr_hdr);
// void add_pim_accept_hdr(struct rte_mbuf *p, struct pim_accept_hdr* pim_accept_hdr);
// void add_pim_ack_hdr(struct rte_mbuf *p, struct pim_ack_hdr* pim_ack_hdr);
// void add_pim_data_hdr(struct rte_mbuf *p, struct pim_data_hdr* pim_data_hdr);
// void add_pim_flow_sync_hdr(struct rte_mbuf *p, struct pim_flow_sync_hdr* pim_flow_sync_hdr);
#endif

