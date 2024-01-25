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
	
}

int disable_dpdk_accept_args(
	int argc, 
	char *argv[], 
	char *dpdk_argv[], 
	char **pci_addr_arg, 
	char **devarg)
{
	bool prev_arg_was_a = false; // indicates prev arg was -a followed by space

	for (int i=0; i<argc; i++) {		
		if (prev_arg_was_a) {
			// This arg should be the PCI BDF.
			// Save it as pci_addr_arg, then
			// replace it with the null PCI address.
			dpdk_argv[i] = strdup("00:00.0");
			*pci_addr_arg = strdup(argv[i]);
			prev_arg_was_a = false;
			continue;
		}

		if (strncmp(argv[i], "-a", 2) != 0) {
			// copy the non-"-a" args
			dpdk_argv[i] = strdup(argv[i]);
			continue;
		}

		if (strlen(argv[i]) == 2) {
			// copy the "-a", next time around replace the arg
			dpdk_argv[i] = strdup(argv[i]);
			prev_arg_was_a = true;
			continue;
		}

		// This arg is the PCI BDF.
		// Save it as pci_addr_arg, then
		// replace it with the null PCI address.
		*pci_addr_arg = strdup(argv[i] + 2); // skip the -a prefix
		dpdk_argv[i] = strdup("-a00:00.0");
	}

	if (!*pci_addr_arg) {
		return -1;
	}

	char * comma = strchr(*pci_addr_arg, ',');
	if (comma) {
		*comma = '\0';
		*devarg = comma + 1;
	} else {
		*devarg = NULL;
	}
	return argc;
}
