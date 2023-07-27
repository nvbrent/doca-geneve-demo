#include <doca_argp.h>
#include <doca_log.h>

#include "geneve_demo.h"

DOCA_LOG_REGISTER(GENEVE_ARGP);

static doca_error_t
sample_callback(void *config, void *param)
{
	// struct geneve_demo_config * sample = config;
	// sample->sample_flag = *(bool *)param;
	return DOCA_SUCCESS;
}

void
geneve_demo_register_argp_params(void)
{
	struct doca_argp_param * sample_flag_param = NULL;
	int ret = doca_argp_param_create(&sample_flag_param);
	if (ret != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(ret));
	doca_argp_param_set_short_name(sample_flag_param, "f");
	doca_argp_param_set_long_name(sample_flag_param, "flag");
	doca_argp_param_set_description(sample_flag_param, "Sets the sample flag");
	doca_argp_param_set_callback(sample_flag_param, sample_callback);
	doca_argp_param_set_type(sample_flag_param, DOCA_ARGP_TYPE_BOOLEAN);
	ret = doca_argp_register_param(sample_flag_param);
	if (ret != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(ret));
	
	// Repeat for each parameter
}
