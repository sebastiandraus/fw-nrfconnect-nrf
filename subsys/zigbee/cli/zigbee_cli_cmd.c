/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <version.h>
#include <string.h>
#include <shell/shell.h>

#include <zboss_api.h>
#include <zb_error_handler.h>
#include <zb_version.h>
#include "zigbee_cli.h"
#include "zigbee_cli_utils.h"

#define DEBUG_HELP \
	"Return state of debug mode.\n"

#define DEBUG_ON_HELP \
	"Turn on debug mode.\n"

#define DEBUG_OFF_HELP \
	"Turn off debug mode.\n"

#define DEBUG_WARN_MSG \
	"You are about to turn the debug mode on. This unblocks several\n" \
	"additional commands in the CLI. They can render the device " \
	"unstable.\nIt is implied that you know what you are doing."

/**@brief Print CLI, ZBOSS and Zephyr kernel version
 *
 * @code
 * version
 * @endcode
 *
 * @code
 * > version
 * CLI: Jul 2 2020 16:14:18
 * ZBOSS: 3.1.0.59
 * Done
 * @endcode
 */
static int cmd_version(const struct shell *shell, size_t argc, char **argv)
{
	shell_print(shell, "CLI: " __DATE__ " " __TIME__);
	shell_print(shell, "ZBOSS: %d.%d.0.%d", ZBOSS_MAJOR, ZBOSS_MINOR,
		    ZBOSS_SDK_REVISION);
	shell_print(shell, "Zephyr kernel version: %s", KERNEL_VERSION_STRING);

	print_done(shell, false);
	return 0;
}

/**@brief Perform device reset using NVIC_SystemReset().
 *
 * @code
 * > reset
 * @endcode
 */
static int cmd_reset(const struct shell *shell, size_t argc, char **argv)
{
	NVIC_SystemReset();
	return 0;
}

/**@brief Get state of debug mode in the CLI
 *
 * @code
 * debug
 * @endcode
 */
static int cmd_debug(const struct shell *shell, size_t argc, char **argv)
{
	if (zb_cli_debug_get()) {
		shell_print(shell, "Debug mode is on.");
	} else {
		shell_print(shell, "Debug mode is off.");
	}

	print_done(shell, false);
	return 0;
}

/**@brief Enable debug mode in the shell
 *
 * @code
 * debug on
 * @endcode
 *
 * This command unblocks several additional commands in the shell.
 * They can render the device unstable. It is implied that you know
 * what you are doing.
 */
static int cmd_debug_on_off(const struct shell *shell, size_t argc, char **argv)
{
	if (strcmp(argv[0], "on") == 0) {
		shell_warn(shell, DEBUG_WARN_MSG);
		zb_cli_debug_set(ZB_TRUE);
		shell_print(shell, "Debug mode is on.");
	} else if (strcmp(argv[0], "off") == 0) {
		zb_cli_debug_set(ZB_FALSE);
		shell_print(shell, "Debug mode is off.");
	}

	print_done(shell, false);
	return 0;
}

SHELL_CMD_REGISTER(version, NULL, "Print firmware version", cmd_version);
SHELL_CMD_REGISTER(reset, NULL, "Reset the board", cmd_reset);

SHELL_STATIC_SUBCMD_SET_CREATE(sub_debug,
	SHELL_COND_CMD(CONFIG_ZIGBEE_SHELL_DEBUG_CMD, off, NULL, DEBUG_OFF_HELP, cmd_debug_on_off),
	SHELL_COND_CMD(CONFIG_ZIGBEE_SHELL_DEBUG_CMD, on, NULL, DEBUG_ON_HELP, cmd_debug_on_off),
	SHELL_SUBCMD_SET_END);

SHELL_COND_CMD_REGISTER(CONFIG_ZIGBEE_SHELL_DEBUG_CMD, debug, &sub_debug, DEBUG_HELP, cmd_debug);
