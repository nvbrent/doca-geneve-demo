/*
 * Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#pragma once

#include <rte_hash.h>
#include <geneve_demo.h>

// Returns a hash_table suitable for storing sessions on success; exits with error message on failure.
struct rte_hash * session_ht_create();

// Returns 0 on success; errno otherwise.
int add_session(struct rte_hash * ht, struct session_def *session);

// Returns 0 on success; errno otherwise.
int delete_session(struct rte_hash * ht, session_id_t session_id);
