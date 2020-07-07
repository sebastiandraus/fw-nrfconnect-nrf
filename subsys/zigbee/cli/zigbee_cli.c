/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <shell/shell.h>
#include <shell/shell_uart.h>
#include "zigbee_cli.h"

/* CLI Agent endpoint. */
static zb_uint8_t cli_ep;

#ifndef DEVELOPMENT_TODO
#error "Do we need app timer here?"
// TODO: VERiFY IF NEEDED
/* Counter timer. */
APP_TIMER_DEF(m_timer_0);
#endif

static zb_bool_t m_debug_mode = ZB_FALSE;

/* Zigbee stack processing suspension indicator. */
static zb_bool_t m_suspended = ZB_FALSE;

LOG_MODULE_REGISTER(cli, CONFIG_ZIGBEE_CLI_LOG_LEVEL);

void zb_cli_init(void)
{
#ifdef CONFIG_ZIGBEE_SHELL_PROMPT
	zb_set_cli_shell_prompt(CONFIG_ZIGBEE_SHELL_PROMPT);
#endif
}

void zb_set_cli_shell_prompt(const char *new_prompt)
{
#ifdef CONFIG_SHELL_BACKEND_SERIAL
	if(shell_prompt_change(shell_backend_uart_get_ptr(), new_prompt)) {
		LOG_ERR("Can not change shell prompt");
	}
#else
	LOG_ERR("Selected shell is not supported.");
#endif
}

/**@brief Returns the number of the Endpoint used by the CLI.
 */
zb_uint8_t zb_get_cli_endpoint(void)
{
	return cli_ep;
}

/**@brief Sets the number of the Endpoint used by the CLI.
 */
zb_void_t zb_set_cli_endpoint(zb_uint8_t ep)
{
	cli_ep = ep;
}

/**@brief Sets the debug mode.
 */
zb_void_t zb_cli_debug_set(zb_bool_t debug)
{
	m_debug_mode = debug;
}

/**@brief Gets the debug mode.
 */
zb_bool_t zb_cli_debug_get(zb_void_t)
{
	return m_debug_mode;
}

/**@brief Function for suspending the processing of the Zigbee main loop.
 */
zb_void_t zb_cli_suspend(zb_void_t)
{
	m_suspended = ZB_TRUE;
}

/**@brief Function for resuming the processing of the Zigbee main loop.
 */
zb_void_t zb_cli_resume(zb_void_t)
{
	m_suspended = ZB_FALSE;
}

/**@brief Function for getting the state of the Zigbee stack
 *        processing suspension.
 */
zb_bool_t zb_cli_stack_is_suspended(zb_void_t)
{
	return m_suspended;
}
