/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stdlib.h>
#include <shell/shell.h>
#include <nrf_802154.h>
#include <fem/nrf_fem_control_config.h>

#include <zboss_api.h>
#include <zb_error_handler.h>
#include "zigbee_cli.h"
#include "zigbee_cli_utils.h"


/**@brief Activate the Front-End Modules (FEM) by enabling control lines.
 *
 * @code
 * radio fem enable
 * @endcode
 *
 * For more information, see the description of the FEM
 * on the @link_radio_driver Wiki and @ref shared_fem_feature page.
 */
static int cmd_zb_fem(const struct shell *shell, size_t argc, char **argv)
{
#ifndef ENABLE_FEM
	print_error(shell, "FEM support disabled", ZB_FALSE);
	return -ENOEXEC;
#else
	nrf_fem_interface_config_t fem_config;
	int                        err_code;

	/* Read the current configuration. */
	err_code = nrf_fem_interface_configuration_get(&fem_config);
	if (err_code != NRF_SUCCESS) {
		print_error(shell, "Unable to read current FEM configuration",
			    ZB_FALSE);
		return -ENOEXEC;
	}

	/* Check if FEM is enabled. FEM can be enabled only once. */
#if defined(NRF_FEM_CONTROL_DEFAULT_PA_PIN) \
	&& defined(NRF_FEM_CONTROL_DEFAULT_LNA_PIN) \
	&& defined(NRF_FEM_CONTROL_DEFAULT_PDN_PIN)

	if (fem_config.pa_pin_config.enable ||
	    fem_config.lna_pin_config.enable ||
	    fem_config.pdn_pin_config.enable)
#else
	if (fem_config.pa_pin_config.enable ||
	    fem_config.lna_pin_config.enable) {
#endif
		print_error(shell, "FEM already enabled", ZB_FALSE);
		return -ENOEXEC;
	}

	fem_config.pa_pin_config.enable  = 1;
	fem_config.lna_pin_config.enable = 1;
#if defined(NRF_FEM_CONTROL_DEFAULT_PA_PIN) && \
	defined(NRF_FEM_CONTROL_DEFAULT_LNA_PIN) && \
	defined(NRF_FEM_CONTROL_DEFAULT_PDN_PIN)

	fem_config.pdn_pin_config.enable = 1;
#endif

	/* Configure FEM control pins. */
	nrf_fem_gpio_configure();

	/* Update the configuration. */
	err_code = nrf_fem_interface_configuration_set(&fem_config);
	if (err_code != NRF_SUCCESS) {
		print_error(shell, "Unable to update FEM configuration",
			    ZB_FALSE);
		return -ENOEXEC;
	}

	print_done(shell, ZB_FALSE);
	return 0;
#endif
}

/**@brief Configure FEM lines
 *
 * @code
 * radio fem <pa|lna> <pin|polarity> <d:pin|active_high>
 * @endcode
 *
 * The first argument selects the FEM line to configure.
 * The available options are:
 * - pa: Power Amplifier
 * - lna: Low Noise Amplifier
 * - pdn: Power Down control pin
 *
 * The second argument selects which attribute will be changed:
 *  - pin: configures FEM pin number
 *  - polarity: configures FEM pin polarity
 *
 * The third argument is a value for the selected configuration attribute:
 *  - pin: selects the GPIO pin, which controls the FEM line
 *  - active_high: selects the polarity of the pin that activates the FEM line
 *    (Power Amplifier, Low Noise Amplifier or Power Down control,
 *     depending on the first argument).
 *
 * @note The FEM configuration may be applied only before the FEM control
 *       lines are enabled.
 */
static int cmd_zb_fem_line(const struct shell *shell, const char * p_line,
			   size_t argc, char **argv)
{
#ifndef ENABLE_FEM
	print_error(shell, "FEM support disabled", ZB_FALSE);
	return -ENOEXEC;
#else
	nrf_fem_gpiote_pin_config_t  *p_line_config = NULL;
	nrf_fem_interface_config_t    fem_config;
	int                           err_code;
	u8_t                          value;

	/* Read the current configuration. */
	err_code = nrf_fem_interface_configuration_get(&fem_config);
	if (err_code != NRF_SUCCESS) {
		print_error(shell, "Unable to read current FEM configuration",
			    ZB_FALSE);
		return -ENOEXEC;
	}

	/* Check if FEM is enabled. FEM can be enabled only once. */
	if (fem_config.pa_pin_config.enable ||
		fem_config.lna_pin_config.enable) {
		print_error(shell, "Configuration may be changed only if FEM is disabled",
			    ZB_FALSE);
		return -ENOEXEC;
	}

	/* Resolve line name to configuration structure. */
	if (strcmp(p_line, "PA") == 0) {
		p_line_config = &fem_config.pa_pin_config;
	} else if (strcmp(p_line, "LNA") == 0) {
		p_line_config = &fem_config.lna_pin_config;
	}
#if defined(NRF_FEM_CONTROL_DEFAULT_PA_PIN) && \
	defined(NRF_FEM_CONTROL_DEFAULT_LNA_PIN) && \
	defined(NRF_FEM_CONTROL_DEFAULT_PDN_PIN)

	else if (strcmp(p_line, "PDN") == 0) {
		p_line_config = &fem_config.pdn_pin_config;
	}
#endif
	else {
		print_error(shell, "Unsupported line name", ZB_FALSE);
		return -EINVAL;
	}

	/* Parse user input. */
	err_code = sscan_uint8(argv[1], &value);
	if (err_code == 0) {
		print_error(shell, "Incorrect value", ZB_FALSE);
		return -EINVAL;
	}

	/* Resolve configuration value. */
	if (strcmp(argv[0], "pin") == 0) {
		p_line_config->gpio_pin = (u8_t)value;
	} else if (strcmp(argv[0], "polarity") == 0) {
		p_line_config->active_high = (value ? true : false);
	} else {
		print_error(shell, "Unsupported line configuration option",
			    ZB_FALSE);
		return -EINVAL;
	}

	/* Update the configuration. */
	err_code = nrf_fem_interface_configuration_set(&fem_config);
	if (err_code != NRF_SUCCESS) {
		print_error(shell, "Unable to update FEM configuration",
			    ZB_FALSE);
		return -ENOEXEC;
	}

	print_done(shell, ZB_FALSE);
	return 0;
#endif
}

/**@brief Subcommand to configure Power Amplifier line of FEM module.
 *
 * @note For more information see @ref fem_configure_pin
 *       and @ref fem_configure_polarity commands description.
 */
static int cmd_zb_fem_line_pa(const struct shell *shell, size_t argc,
			      char **argv)
{
	return cmd_zb_fem_line(shell, "PA", argc, argv);
}

/**@brief Subcommand to configure Low Noise Amplifier line of FEM module.
 *
 * @note For more information see @ref fem_configure_pin
 *       and @ref fem_configure_polarity commands description.
 */
static int cmd_zb_fem_line_lna(const struct shell *shell, size_t argc,
			       char **argv)
{
	return cmd_zb_fem_line(shell, "LNA", argc, argv);
}

/**@brief Subcommand to configure Power Down line of FEM module.
 *
 * @note For more information see @ref fem_configure_pin
 *       and @ref fem_configure_polarity commands description.
 */
static int cmd_zb_fem_line_pdn(const struct shell *shell, size_t argc,
			       char **argv)
{
	return cmd_zb_fem_line(shell, "PDN", argc, argv);
}

/**@brief Function to set the 802.15.4 channel directly.
 *
 * @code
 * radio channel set <n>
 * @endcode
 *
 * The <n> has to be between 11 and 26 included, since these channels
 * are supported by the driver.
 *
 * @note This function sets the channel directly at runtime,
 *       contrary to the `bdb channel` function, which defines the channels
 *       allowed for the Zigbee network formation.
 */
static int cmd_zb_channel_set(const struct shell *shell, size_t argc,
			      char **argv)
{
	u8_t channel;

	if (!sscan_uint8(argv[1], &channel)) {
		print_error(shell, "Invalid channel", ZB_FALSE);
	} else if ((channel < 11) || (channel > 26)) {
		print_error(shell, "Only channels from 11 to 26 are supported",
			    ZB_FALSE);
	} else {
		nrf_802154_channel_set(channel);
		print_done(shell, ZB_FALSE);

		return 0;
	}

	return -EINVAL;
}

/**@brief Function to get the current 802.15.4 channel.
 *
 * @code
 * radio channel get
 * @endcode
 *
 */
static int cmd_zb_channel_get(const struct shell *shell, size_t argc,
			      char **argv)
{
	shell_print(shell, "Current operating channel: %d",
		    nrf_802154_channel_get());
	print_done(shell, ZB_FALSE);

	return 0;
}


SHELL_STATIC_SUBCMD_SET_CREATE(sub_fem_line_pa,
	SHELL_CMD_ARG(pin, NULL, "Select pin number to use", cmd_zb_fem_line_pa,
		      2, 0),
	SHELL_CMD_ARG(polarity, NULL, "Select active polarity",
		      cmd_zb_fem_line_pa, 2, 0),
	SHELL_SUBCMD_SET_END);

SHELL_STATIC_SUBCMD_SET_CREATE(sub_fem_line_lna,
	SHELL_CMD_ARG(pin, NULL, "Select pin number to use",
		      cmd_zb_fem_line_lna, 2, 0),
	SHELL_CMD_ARG(polarity, NULL, "Select active polarity",
		      cmd_zb_fem_line_lna, 2, 0),
	SHELL_SUBCMD_SET_END);

SHELL_STATIC_SUBCMD_SET_CREATE(sub_fem_line_pdn,
	SHELL_CMD_ARG(pin, NULL, "Select pin number to use",
		      cmd_zb_fem_line_pdn, 2, 0),
	SHELL_CMD_ARG(polarity, NULL, "Select active polarity",
		      cmd_zb_fem_line_pdn, 2, 0),
	SHELL_SUBCMD_SET_END);

SHELL_STATIC_SUBCMD_SET_CREATE(sub_fem,
	SHELL_CMD(pa, &sub_fem_line_pa, "Configure PA control line", NULL),
	SHELL_CMD(lna, &sub_fem_line_lna, "Configure LNA control pin", NULL),
	SHELL_CMD(pdn, &sub_fem_line_pdn, "Configure PDN control pin", NULL),
	SHELL_CMD_ARG(enable, NULL, "Enable FEM", cmd_zb_fem, 1, 0),
	SHELL_SUBCMD_SET_END);

SHELL_STATIC_SUBCMD_SET_CREATE(sub_channel,
	SHELL_CMD_ARG(set, NULL, "Set 802.15.4 channel", cmd_zb_channel_set,
		      2, 0),
	SHELL_CMD_ARG(get, NULL, "Get 802.15.4 channel", cmd_zb_channel_get,
		      1, 0),
	SHELL_SUBCMD_SET_END);

SHELL_STATIC_SUBCMD_SET_CREATE(sub_radio,
	SHELL_CMD(fem, &sub_fem, "Front-end module", NULL),
	SHELL_CMD(channel, &sub_channel, "Get/set channel", NULL),
	SHELL_SUBCMD_SET_END);

SHELL_CMD_REGISTER(radio, &sub_radio, "Radio manipulation", NULL);
