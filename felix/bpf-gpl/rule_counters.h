// Project Calico BPF dataplane programs.
// Copyright (c) 2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_RULE_COUNTERS_H__
#define __CALI_RULE_COUNTERS_H__

#include "types.h"
typedef struct rule_ctr_val {
	__u64 count;
	__u64 ts;
}rule_count_t;

CALI_MAP(cali_rule_ctrs, 1,
		BPF_MAP_TYPE_PERCPU_HASH,
		__u64, rule_count_t, MAX_RULE_IDS, 0, MAP_PIN_GLOBAL)

static CALI_BPF_INLINE void update_rule_counters(struct cali_tc_state *state) {
	int ret = 0;
	rule_count_t *rule_count_val = NULL;
	rule_count_t rule_val = {0};
	for (int i = 0; i < MAX_RULE_IDS; i++) {
		if (i >= state->rules_hit) {
			break;
		}
		__u64 ruleId = state->rule_ids[i];
		rule_count_val = cali_rule_ctrs_lookup_elem(&ruleId);
		if (rule_count_val) {
			rule_count_val->count++;
			ret = cali_rule_ctrs_update_elem(&ruleId, rule_count_val, 0);
			if (ret != 0) {
				CALI_DEBUG("error updating rule counter map entry 0x%x\n", ruleId);
			} else {
				CALI_DEBUG("rule counter map updated 0x%x\n", ruleId);
			}
			return;
		}
		CALI_DEBUG("Sridhar: update rule id\n");
		rule_val.count = 1;
		ret = cali_rule_ctrs_update_elem(&ruleId, &rule_val, 0);
			if (ret != 0) {
				CALI_DEBUG("error creating rule counter map entry 0x%x\n", ruleId);
			} else {
				CALI_DEBUG("rule counter map created 0x%x\n", ruleId);
			}
	}
}

#endif /* __CALI_COUNTERS_H__ */
