#include <rte_memcpy.h>
#include "header.h"

void parse_header(struct rte_mbuf* p, struct ipv4_hdr** ipv4_hdr, struct pim_hdr** pim_hdr) {
	uint32_t offset = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr);
	// get ip header
	*ipv4_hdr = rte_pktmbuf_mtod_offset(p, struct ipv4_hdr *, sizeof(struct ether_hdr));
	// get pim header
	*pim_hdr = rte_pktmbuf_mtod_offset(p, struct pim_hdr *, offset);
}
void add_ether_hdr(struct rte_mbuf* p, struct ether_addr* dst) {
	struct ether_hdr *eth_hdr;
	eth_hdr = rte_pktmbuf_mtod(p, struct ether_hdr *);
	eth_hdr->ether_type = rte_cpu_to_be_16(0x0800);
	ether_addr_copy(dst, &eth_hdr->d_addr);
	ether_addr_copy(&params.ether_addr, &eth_hdr->s_addr);

}
// void add_ip_hdr(struct rte_mbuf* p, struct ipv4_hdr* ipv4_hdr) {
// 	struct ipv4_hdr* hdr;
// 	uint32_t offset = sizeof(struct ether_hdr);
// 	hdr = rte_pktmbuf_mtod_offset(p, struct ipv4_hdr*, offset);
// 	rte_memcpy(hdr, ipv4_hdr, sizeof(struct ipv4_hdr));
// }
// void add_pim_hdr(struct rte_mbuf* p, struct pim_hdr* pim_hdr) {
// 	struct  pim_hdr* hdr;
// 	uint32_t offset = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr);
// 	hdr = rte_pktmbuf_mtod_offset(p, struct pim_hdr*, offset);
// 	rte_memcpy(hdr, pim_hdr, sizeof(struct pim_hdr));
// }
// void add_pim_flow_sync_hdr(struct rte_mbuf *p, struct pim_flow_sync_hdr* pim_flow_sync_hdr) {
// 	struct pim_flow_sync_hdr *hdr;
// 	uint32_t offset = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) +
// 	sizeof(struct pim_hdr);
// 	hdr = rte_pktmbuf_mtod_offset(p, struct pim_flow_sync_hdr*, offset);
// 	rte_memcpy(hdr, pim_flow_sync_hdr, sizeof(struct pim_flow_sync_hdr));
// }
// void add_pim_rts_hdr(struct rte_mbuf *p, struct pim_rts_hdr* pim_rts_hdr) {
// 	struct pim_rts_hdr *hdr;
// 	uint32_t offset = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) +
// 	sizeof(struct pim_hdr);
// 	hdr = rte_pktmbuf_mtod_offset(p, struct pim_rts_hdr*, offset);
// 	rte_memcpy(hdr, pim_rts_hdr, sizeof(struct pim_rts_hdr));
// }
// void add_pim_grant_hdr(struct rte_mbuf *p, struct pim_grant_hdr* pim_grant_hdr) {
// 	struct pim_grant_hdr *hdr;
// 	uint32_t offset = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) +
// 	sizeof(struct pim_hdr);
// 	hdr = rte_pktmbuf_mtod_offset(p, struct pim_grant_hdr*, offset);
// 	rte_memcpy(hdr, pim_grant_hdr, sizeof(struct pim_grant_hdr));
// }
// void add_pim_grantr_hdr(struct rte_mbuf *p, struct pim_grantr_hdr* pim_grantr_hdr) {
// 	struct pim_grantr_hdr *hdr;
// 	uint32_t offset = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) +
// 	sizeof(struct pim_hdr);
// 	hdr = rte_pktmbuf_mtod_offset(p, struct pim_grantr_hdr*, offset);
// 	rte_memcpy(hdr, pim_grantr_hdr, sizeof(struct pim_grantr_hdr));
// }
// void add_pim_accept_hdr(struct rte_mbuf *p, struct pim_accept_hdr* pim_accept_hdr) {
// 	struct pim_accept_hdr *hdr;
// 	uint32_t offset = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) +
// 	sizeof(struct pim_hdr) + sizeof(struct pim_accept_hdr);
// 	hdr = rte_pktmbuf_mtod_offset(p, struct pim_accept_hdr*, offset);
// 	rte_memcpy(hdr, pim_accept_hdr, sizeof(struct pim_accept_hdr));
// }

// void add_pim_data_hdr(struct rte_mbuf *p, struct pim_data_hdr* pim_data_hdr) {
// 	struct pim_data_hdr *hdr;
// 	uint32_t offset = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) +
// 	sizeof(struct pim_hdr);
// 	hdr = rte_pktmbuf_mtod_offset(p, struct pim_data_hdr*, offset);
// 	rte_memcpy(hdr, pim_data_hdr, sizeof(struct pim_data_hdr));
// }
// void add_pim_ack_hdr(struct rte_mbuf *p, struct pim_ack_hdr* pim_ack_hdr) {
// 	struct pim_ack_hdr *hdr;
// 	uint32_t offset = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) +
// 	sizeof(struct pim_hdr);
// 	hdr = rte_pktmbuf_mtod_offset(p, struct pim_ack_hdr*, offset);
// 	rte_memcpy(hdr, pim_ack_hdr, sizeof(struct pim_ack_hdr));
// }