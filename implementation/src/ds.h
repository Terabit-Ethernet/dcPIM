#ifndef DS_H
#define DS_H

#include <rte_hash.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_timer.h>
#include <rte_mbuf.h>
#include <rte_jhash.h>
// initialize data structure
struct rte_hash* create_hash_table(const char* name, uint32_t key_len, uint32_t num_entries, uint8_t flag, uint32_t socket_id);
struct rte_ring* create_ring(const char*name, uint32_t entry_len, uint32_t num_entries, unsigned flags, uint32_t socket_id);
struct rte_mempool* create_mempool(const char* name, uint32_t entry_len, uint32_t num_entries, uint32_t socket_id);

void insert_table_entry( struct rte_hash* hash, uint32_t key, void* rtp_f);
void delete_table_entry( struct rte_hash* hash, uint32_t key);
void* lookup_table_entry(struct rte_hash* hash, uint32_t key);
void enqueue_ring (struct rte_ring* rte_ring, void* entry);
void* dequeue_ring (struct rte_ring* rte_ring);

#endif