#include <rte_memcpy.h>
#include "header.h"

void parse_header(struct rte_mbuf* p, struct ipv4_hdr** ipv4_hdr, struct pim_hdr** pim_hdr) {
	uint32_t offset = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr);
	// get ip header
	*ipv4_hdr = rte_pktmbuf_mtod_offset(p, struct ipv4_hdr *, sizeof(struct ether_hdr));
	// get pim header
	*pim_hdr = rte_pktmbuf_mtod_offset(p, struct pim_hdr *, offset);
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
void add_pim_hdr(struct rte_mbuf* p, struct pim_hdr* pim_hdr) {
	struct  pim_hdr* hdr;
	uint32_t offset = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr);
	hdr = rte_pktmbuf_mtod_offset(p, struct pim_hdr*, offset);
	rte_memcpy(hdr, pim_hdr, sizeof(struct pim_hdr));
}
void add_pim_rts_hdr(struct rte_mbuf *p, struct pim_rts_hdr* pim_rts_hdr) {
	struct pim_rts_hdr *hdr;
	uint32_t offset = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) +
	sizeof(struct pim_hdr);
	hdr = rte_pktmbuf_mtod_offset(p, struct pim_rts_hdr*, offset);
	rte_memcpy(hdr, pim_rts_hdr, sizeof(struct pim_rts_hdr));
}
void add_pim_gosrc_hdr(struct rte_mbuf *p, struct pim_gosrc_hdr* pim_gosrc_hdr) {
	struct pim_gosrc_hdr *hdr;
	uint32_t offset = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) +
	sizeof(struct pim_hdr);
	hdr = rte_pktmbuf_mtod_offset(p, struct pim_gosrc_hdr*, offset);
	rte_memcpy(hdr, pim_gosrc_hdr, sizeof(struct pim_gosrc_hdr));
}
void add_pim_listsrc_hdr(struct rte_mbuf *p, struct pim_listsrc_hdr* pim_listsrc_hdr) {
	struct pim_listsrc_hdr *hdr;
	uint32_t offset = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) +
	sizeof(struct pim_hdr);
	hdr = rte_pktmbuf_mtod_offset(p, struct pim_listsrc_hdr*, offset);
	rte_memcpy(hdr, pim_listsrc_hdr, sizeof(struct pim_listsrc_hdr));
}
void add_pim_nrts_hdr(struct rte_mbuf *p, struct pim_nrts_hdr* pim_nrts_hdr) {
	struct pim_nrts_hdr *hdr;
	uint32_t offset = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) +
	sizeof(struct pim_hdr) + sizeof(struct pim_listsrc_hdr);
	hdr = rte_pktmbuf_mtod_offset(p, struct pim_nrts_hdr*, offset);
	rte_memcpy(hdr, pim_nrts_hdr, sizeof(struct pim_nrts_hdr));
}
void add_pim_token_hdr(struct rte_mbuf *p, struct pim_token_hdr* pim_token_hdr) {
	struct pim_token_hdr *hdr;
	uint32_t offset = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) +
	sizeof(struct pim_hdr);
	hdr = rte_pktmbuf_mtod_offset(p, struct pim_token_hdr*, offset);
	rte_memcpy(hdr, pim_token_hdr, sizeof(struct pim_token_hdr));

}
void add_pim_data_hdr(struct rte_mbuf *p, struct pim_data_hdr* pim_data_hdr) {
	struct pim_data_hdr *hdr;
	uint32_t offset = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) +
	sizeof(struct pim_hdr);
	hdr = rte_pktmbuf_mtod_offset(p, struct pim_data_hdr*, offset);
	rte_memcpy(hdr, pim_data_hdr, sizeof(struct pim_data_hdr));
}
void add_pim_ack_hdr(struct rte_mbuf *p, struct pim_ack_hdr* pim_ack_hdr) {
	struct pim_ack_hdr *hdr;
	uint32_t offset = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) +
	sizeof(struct pim_hdr);
	hdr = rte_pktmbuf_mtod_offset(p, struct pim_ack_hdr*, offset);
	rte_memcpy(hdr, pim_ack_hdr, sizeof(struct pim_ack_hdr));
}