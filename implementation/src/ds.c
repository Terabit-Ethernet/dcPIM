#include "ds.h"

// data structure
struct rte_hash* create_hash_table(const char* name, uint32_t key_len, uint32_t num_entries, uint8_t flag, uint32_t socket_id)
{
        struct rte_hash *h;
        /* create table */
        struct rte_hash_parameters hash_params = {
                .entries = num_entries, 
                .key_len = key_len,
                .socket_id = socket_id,
                .hash_func = rte_jhash,
                .hash_func_init_val = 0
        };
        hash_params.name = name;
        if(flag != 0) {
	        hash_params.extra_flag = flag;
        }
        h = rte_hash_create(&hash_params);
        if (h == NULL){
            rte_exit(EXIT_FAILURE,
                            "Problem creating the hash table for node %d\n",
                            socket_id);
        }
        return h;
}

struct rte_mempool* create_mempool(const char* name, uint32_t entry_len, uint32_t num_entries, uint32_t socket_id) {
	struct rte_mempool* pool = rte_pktmbuf_pool_create(name, num_entries,
		0, 0, entry_len,
		socket_id);
    if (pool == NULL)
            rte_exit(EXIT_FAILURE, "Buffer pool creation error\n");
    return pool;
}

struct rte_ring* create_ring(const char*name, uint32_t entry_len, uint32_t num_entries, unsigned flags, uint32_t socket_id) {

	struct rte_ring* ring = rte_ring_create(name,
                rte_align32pow2(entry_len * num_entries), socket_id, flags);
	if(ring == NULL) {
        rte_exit(EXIT_FAILURE,
                        "Problem creating the ring for node %d\n",
                        socket_id);
	}
	return ring;
}

void enqueue_ring (struct rte_ring* rte_ring, void* entry) {
	int ret = rte_ring_enqueue(rte_ring,
               entry);
	if(ret == -ENOBUFS) {
        rte_exit(EXIT_FAILURE,
                 " Not enough room in the ring to enqueue; no object is enqueued\n");
	}
}

void* dequeue_ring (struct rte_ring* rte_ring) {
	void* obj;
	int ret = rte_ring_dequeue(rte_ring, &obj);

	if(ret != 0)
		return NULL;
	return obj;
}

void insert_table_entry(struct rte_hash* hash, uint32_t key, void* rtp_f){
	int ret = rte_hash_add_key_data(hash, &key, (void*)rtp_f);
	if(ret != 0) {
		if (ret == -EINVAL) {
	        printf("%d: invalid parameter\n", __LINE__);
	        rte_exit(EXIT_FAILURE, "fail");
		} else {
	        printf("%d: flow hash table has no space:\n", __LINE__);
	        rte_exit(EXIT_FAILURE, "fail");
		}
	}
}
void delete_table_entry(struct rte_hash* hash, uint32_t key) {
	rte_hash_del_key(hash, &key);
}

void* lookup_table_entry(struct rte_hash* hash, uint32_t key) {
	void* temp = NULL;
	int ret = rte_hash_lookup_data(hash, &key, (void*)&temp);
	if(ret < 0)
		return NULL;
	return temp;
}