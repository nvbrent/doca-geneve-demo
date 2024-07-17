#include <stdlib.h>

#include <doca_argp.h>
#include <doca_log.h>
#include <rte_ethdev.h>

#include "geneve_demo.h"

DOCA_LOG_REGISTER(GENEVE_ARGP);

static doca_error_t
config_callback(void *param, void *config_voidp)
{
	struct geneve_demo_config * config = config_voidp;
	const char *param_str = param;

	FILE *fd = fopen(param_str, "r");
	if (!fd) {
		DOCA_LOG_ERR("Unable to open vnet config file: %s", param_str);
	}
	fclose(fd);

	config->vnet_config_file = strdup(param_str);
	DOCA_LOG_INFO("Selected vnet config file: %s", config->vnet_config_file);
	return DOCA_SUCCESS;
}

static doca_error_t
sample_rate_callback(void *param, void *config_voidp)
{
	struct geneve_demo_config * config = config_voidp;
	const char *param_str = param;

	if (!strcmp(param_str, "none")) {
		config->sample_mask = UINT32_MAX;
		DOCA_LOG_INFO("Sampling disabled");
	} else {
		int log2_sample_rate = atoi(param_str);
		if (log2_sample_rate < 0 || log2_sample_rate > 16) {
			DOCA_LOG_ERR("The log2_sample_rate must be 'none' or in the range of 0..16");
			return DOCA_ERROR_INVALID_VALUE;
		}
		config->sample_mask = (uint16_t)((1 << log2_sample_rate) - 1);
		DOCA_LOG_INFO("The log2_sample_rate is set to %d, mask 0x%x", log2_sample_rate, config->sample_mask);
	}

	return DOCA_SUCCESS;
}

void
geneve_demo_register_argp_params(void)
{
	struct doca_argp_param * param = NULL;
	int ret = doca_argp_param_create(&param);
	if (ret != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_error_get_descr(ret));
	doca_argp_param_set_short_name(param, "c");
	doca_argp_param_set_long_name(param, "config");
	doca_argp_param_set_description(param, "Path to the vnet config file");
	doca_argp_param_set_callback(param, config_callback);
	doca_argp_param_set_mandatory(param);
	doca_argp_param_set_type(param, DOCA_ARGP_TYPE_STRING);
	ret = doca_argp_register_param(param);
	if (ret != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to register program param: %s", doca_error_get_descr(ret));
	
	ret = doca_argp_param_create(&param);
	if (ret != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_error_get_descr(ret));
	doca_argp_param_set_short_name(param, "r");
	doca_argp_param_set_long_name(param, "sample-rate");
	doca_argp_param_set_description(param, "Sets the log2 sample rate: 0: 100%, 1: 50%, ... 16: 1.5e-3% or 'none'");
	doca_argp_param_set_callback(param, sample_rate_callback);
	doca_argp_param_set_type(param, DOCA_ARGP_TYPE_STRING); // check for none, else parse the integer
	ret = doca_argp_register_param(param);
	if (ret != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to register program param: %s", doca_error_get_descr(ret));
}
