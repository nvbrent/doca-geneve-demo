#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_malloc.h>
#include <rte_errno.h>

#include <doca_log.h>

#include <geneve_demo_session_hashtable.h>

#define MAX_HT_ENTRIES (100 * 1024)

DOCA_LOG_REGISTER(GENEVE_SESSION_HT)

struct rte_hash_parameters sample_ht_params = {
	.name = "session_ht",
	.entries = MAX_HT_ENTRIES,
	.key_len = sizeof(session_id_t),
	.hash_func = rte_jhash,
	.hash_func_init_val = 0,
	.extra_flag = 0, // see RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF
};

struct rte_hash *
session_ht_create()
{
	struct rte_hash * ht = rte_hash_create(&sample_ht_params);
	if (!ht) {
		rte_exit(EXIT_FAILURE, "failed to initialize session hash_table: %d (%s)\n", rte_errno, rte_strerror(rte_errno));
	}
	return ht;
}

int
add_session(struct rte_hash * ht, struct session_def *session)
{
	int res = rte_hash_add_key_data(ht, &session->session_id, &session);
	if (res) {
		DOCA_LOG_ERR("Failed to add session %ld to hash_table: %d (%s)",
			session->session_id, res, doca_get_error_string(res));
	}
	DOCA_LOG_DBG("Added session %ld", session->session_id);
	return res;
}

int
delete_session(struct rte_hash * ht, session_id_t session_id)
{
	struct session_def * lookup = NULL;
	int res = rte_hash_lookup_data(ht, &session_id, (void**)&lookup);
	if (res >= 0) {
		rte_hash_del_key(ht, &session_id);
		rte_free(lookup);
		return 0;
	}
	DOCA_LOG_ERR("Failed to delete session %ld from hash_table", session_id);
	return res;
}
