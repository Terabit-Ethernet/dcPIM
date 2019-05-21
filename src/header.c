#include <rte_memcpy.h>
#include "header.h"

void parse_header(struct rte_mbuf* p, struct ipv4_hdr** ipv4_hdr, struct ruf_hdr** ruf_hdr) {
	uint32_t offset = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr);
	// get ip header
	*ipv4_hdr = rte_pktmbuf_mtod_offset(p, struct ipv4_hdr *, sizeof(struct ether_hdr));
	// get ruf header
	*ruf_hdr = rte_pktmbuf_mtod_offset(p, struct ruf_hdr *, offset);
}
void add_ether_hdr(struct rte_mbuf* p) {
	struct ether_hdr *eth_hdr;
	eth_hdr = rte_pktmbuf_mtod(p, struct ether_hdr *);
	eth_hdr->ether_type = htons(0x0800);
	eth_hdr->d_addr.addr_bytes[0] = 0;

}
void add_ip_hdr(struct rte_mbuf* p, struct ipv4_hdr* ipv4_hdr) {
	struct ipv4_hdr* hdr;
	uint32_t offset = sizeof(struct ether_hdr);
	hdr = rte_pktmbuf_mtod_offset(p, struct ipv4_hdr*, offset);
	rte_memcpy(hdr, ipv4_hdr, sizeof(struct ipv4_hdr));
}
void add_ruf_hdr(struct rte_mbuf* p, struct ruf_hdr* ruf_hdr) {
	struct  ruf_hdr* hdr;
	uint32_t offset = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr);
	hdr = rte_pktmbuf_mtod_offset(p, struct ruf_hdr*, offset);
	rte_memcpy(hdr, ruf_hdr, sizeof(struct ruf_hdr));
}
void add_ruf_rts_hdr(struct rte_mbuf *p, struct ruf_rts_hdr* ruf_rts_hdr) {
	struct ruf_rts_hdr *hdr;
	uint32_t offset = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) +
	sizeof(struct ruf_hdr);
	hdr = rte_pktmbuf_mtod_offset(p, struct ruf_rts_hdr*, offset);
	rte_memcpy(hdr, ruf_rts_hdr, sizeof(struct ruf_rts_hdr));
}
void add_ruf_gosrc_hdr(struct rte_mbuf *p, struct ruf_gosrc_hdr* ruf_gosrc_hdr) {
	struct ruf_gosrc_hdr *hdr;
	uint32_t offset = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) +
	sizeof(struct ruf_hdr);
	hdr = rte_pktmbuf_mtod_offset(p, struct ruf_gosrc_hdr*, offset);
	rte_memcpy(hdr, ruf_gosrc_hdr, sizeof(struct ruf_gosrc_hdr));
}
void add_ruf_listsrc_hdr(struct rte_mbuf *p, struct ruf_listsrc_hdr* ruf_listsrc_hdr) {
	struct ruf_listsrc_hdr *hdr;
	uint32_t offset = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) +
	sizeof(struct ruf_hdr);
	hdr = rte_pktmbuf_mtod_offset(p, struct ruf_listsrc_hdr*, offset);
	rte_memcpy(hdr, ruf_listsrc_hdr, sizeof(struct ruf_listsrc_hdr));
}
void add_ruf_nrts_hdr(struct rte_mbuf *p, struct ruf_nrts_hdr* ruf_nrts_hdr) {
	struct ruf_nrts_hdr *hdr;
	uint32_t offset = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) +
	sizeof(struct ruf_hdr) + sizeof(struct ruf_listsrc_hdr);
	hdr = rte_pktmbuf_mtod_offset(p, struct ruf_nrts_hdr*, offset);
	rte_memcpy(hdr, ruf_nrts_hdr, sizeof(struct ruf_nrts_hdr));
}
void add_ruf_token_hdr(struct rte_mbuf *p, struct ruf_token_hdr* ruf_token_hdr) {
	struct ruf_token_hdr *hdr;
	uint32_t offset = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) +
	sizeof(struct ruf_hdr);
	hdr = rte_pktmbuf_mtod_offset(p, struct ruf_token_hdr*, offset);
	rte_memcpy(hdr, ruf_token_hdr, sizeof(struct ruf_token_hdr));

}
void add_ruf_data_hdr(struct rte_mbuf *p, struct ruf_data_hdr* ruf_data_hdr) {
	struct ruf_data_hdr *hdr;
	uint32_t offset = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) +
	sizeof(struct ruf_hdr);
	hdr = rte_pktmbuf_mtod_offset(p, struct ruf_data_hdr*, offset);
	rte_memcpy(hdr, ruf_data_hdr, sizeof(struct ruf_data_hdr));
}
void add_ruf_ack_hdr(struct rte_mbuf *p, struct ruf_ack_hdr* ruf_ack_hdr) {
	struct ruf_ack_hdr *hdr;
	uint32_t offset = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) +
	sizeof(struct ruf_hdr);
	hdr = rte_pktmbuf_mtod_offset(p, struct ruf_ack_hdr*, offset);
	rte_memcpy(hdr, ruf_ack_hdr, sizeof(struct ruf_ack_hdr));
}