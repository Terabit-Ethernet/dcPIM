#include <linux/module.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/vmalloc.h>
#include <linux/memblock.h>

#include <net/addrconf.h>
#include <net/inet_connection_sock.h>
#include <net/inet_hashtables.h>
#include <net/secure_seq.h>
#include <net/ip.h>
// #include <net/tcp.h>
#include <net/sock_reuseport.h>
#include "dcpim_hashtables.h"
#include "linux_dcpim.h"
#include "dcpim_impl.h"

void* allocate_hash_table(const char *tablename,
				     unsigned long bucketsize,
				     unsigned long numentries,
				     int scale,
				     int flags,
				     unsigned int *_hash_shift,
				     unsigned int *_hash_mask,
				     unsigned long low_limit,
				     unsigned long high_limit) {
	unsigned long long max = high_limit;
	unsigned long log2qty, size;
	void *table = NULL;
	gfp_t gfp_flags;
	numentries = roundup_pow_of_two(numentries);

	max = min(max, 0x80000000ULL);

	if (numentries < low_limit)
		numentries = low_limit;
	if (numentries > max)
		numentries = max;

	log2qty = ilog2(numentries);
	gfp_flags = (flags & HASH_ZERO) ? GFP_ATOMIC | __GFP_ZERO : GFP_ATOMIC;

	size = bucketsize << log2qty;

	table = vmalloc(size);

	if (!table)
		panic("Failed to allocate %s hash table\n", tablename);

	if (_hash_shift)
		*_hash_shift = log2qty;
	if (_hash_mask)
		*_hash_mask = (1 << log2qty) - 1;

	return table;
}

void dcpim_hashtable_init(struct inet_hashinfo* hashinfo, unsigned long thash_entries) {
		int i = 0;
        inet_hashinfo2_init_mod(hashinfo);
        hashinfo->bind_bucket_cachep =
                kmem_cache_create("dcpim_bind_bucket",
                                  sizeof(struct inet_bind_bucket), 0,
                                  SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL);

        /* Size and allocate the main established and bind bucket
         * hash tables.
         *

         * The methodology is similar to that of the buffer cache.
         */
        hashinfo->ehash =
                allocate_hash_table("DCPIM established",
                                        sizeof(struct inet_ehash_bucket),
                                        thash_entries ? thash_entries : 524288 ,
                                        17, /* one slot per 128 KB of memory */
                                        0,
                                        NULL,
                                        &hashinfo->ehash_mask,
                                        0,
                                        thash_entries ? 0 : 512 * 1024);
        for (i = 0; i <= hashinfo->ehash_mask; i++)
                INIT_HLIST_NULLS_HEAD(&hashinfo->ehash[i].chain, i);

        if (inet_ehash_locks_alloc(hashinfo))
                panic("DCPIM: failed to alloc ehash_locks");
        hashinfo->bhash =
                allocate_hash_table("DCPIM bind",
                                        sizeof(struct inet_bind_hashbucket),
                                        hashinfo->ehash_mask + 1,
                                        17, /* one slot per 128 KB of memory */
                                        0,
                                        &hashinfo->bhash_size,
                                        NULL,
                                        0,
                                        64 * 1024);
        hashinfo->bhash_size = 1U << hashinfo->bhash_size;
        for (i = 0; i < hashinfo->bhash_size; i++) {
                spin_lock_init(&hashinfo->bhash[i].lock);
                INIT_HLIST_HEAD(&hashinfo->bhash[i].chain);
        }
	/* TO DO: Add memory error handling logic */
}

void dcpim_hashtable_destroy(struct inet_hashinfo* hashinfo) {
	vfree(hashinfo->bhash);
	kvfree(hashinfo->ehash_locks);
	kmem_cache_destroy(hashinfo->bind_bucket_cachep);
	vfree(hashinfo->ehash);
	inet_hashinfo2_free_mod(&dcpim_hashinfo);
}