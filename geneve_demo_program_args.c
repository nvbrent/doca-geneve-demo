#include <doca_argp.h>
#include <doca_log.h>
#include <rte_ethdev.h>

#include "geneve_demo.h"

DOCA_LOG_REGISTER(GENEVE_ARGP);

// static doca_error_t
// dmac_callback(void *param, void *config_voidp)
// {
// 	struct geneve_demo_config * config = config_voidp;
// 	const char *param_str = param;

// 	int octets[RTE_ETHER_ADDR_LEN];
// 	int num_octets = sscanf(param_str, "%x:%x:%x:%x:%x:%x",
// 		&octets[0], &octets[1],
// 		&octets[2], &octets[3],
// 		&octets[4], &octets[5]);
// 	if (num_octets != 6) {
// 		DOCA_LOG_ERR("Failed to parse DMAC: %s", param_str);
// 		return DOCA_ERROR_INVALID_VALUE;
// 	}
// 	for (int i=0; i<RTE_ETHER_ADDR_LEN; i++) {
// 		config->outer_dmac.addr_bytes[i] = (uint8_t)octets[i];
// 	}
// 	DOCA_LOG_INFO("Selected DMAC " RTE_ETHER_ADDR_PRT_FMT, RTE_ETHER_ADDR_BYTES(&config->outer_dmac));
// 	return DOCA_SUCCESS;
// }


void
geneve_demo_register_argp_params(void)
{
	// TODO: register argp for path to vnet config file

	// struct doca_argp_param * dmac_param = NULL;
	// int ret = doca_argp_param_create(&dmac_param);
	// if (ret != DOCA_SUCCESS)
	// 	DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(ret));
	// doca_argp_param_set_short_name(dmac_param, "d");
	// doca_argp_param_set_long_name(dmac_param, "dmac");
	// doca_argp_param_set_description(dmac_param, "Sets the destination MAC addr");
	// doca_argp_param_set_callback(dmac_param, dmac_callback);
	// doca_argp_param_set_type(dmac_param, DOCA_ARGP_TYPE_STRING);
	// ret = doca_argp_register_param(dmac_param);
	// if (ret != DOCA_SUCCESS)
	// 	DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(ret));
	
}
