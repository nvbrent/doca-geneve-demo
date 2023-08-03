#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_malloc.h>

#include "geneve_demo.h"

#define MAX_HT_ENTRIES 4096

struct sample_key
{
	rte_be32_t src_ip;
	rte_be32_t dst_ip;
};

struct sample_entry
{
	struct sample_key key;
	uint64_t num_packets;
	uint64_t num_bytes;
};

struct rte_hash_parameters sample_ht_params = {
	.name = "sample_ht",
	.entries = MAX_HT_ENTRIES,
	.key_len = sizeof(struct sample_key),
	.hash_func = rte_jhash,
	.hash_func_init_val = 0,
	.extra_flag = 0, // see RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF
};

void
sample_hash_ops(void)
{
	struct rte_hash * ht = rte_hash_create(&sample_ht_params);

	struct sample_entry * entry = rte_zmalloc(NULL, sizeof(struct sample_entry), 0);
	entry->key.src_ip = RTE_BE32(0x11223344);
	entry->key.dst_ip = RTE_BE32(0x55667788);
	entry->num_packets = 1;
	entry->num_bytes = 0x1000;

	rte_hash_add_key_data(ht, &entry->key, entry);

	struct sample_key lookup_key = {
		.src_ip = RTE_BE32(0x11223344),
		.dst_ip = RTE_BE32(0x55667788),
	};
	struct sample_entry * lookup = NULL;
	if (rte_hash_lookup_data(ht, &lookup_key, (void**)&lookup) >= 0)
	{
		rte_hash_del_key(ht, &lookup_key);
		rte_free(lookup);
	}
}
