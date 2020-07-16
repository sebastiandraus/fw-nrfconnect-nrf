/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <init.h>
#include <shell/shell.h>
#include <shell/shell_uart.h>

#include <zb_nrf_platform.h>
#include "zigbee_cli.h"

/* CLI Agent endpoint. */
static zb_uint8_t cli_ep;

#ifndef DEVELOPMENT_TODO
#error "Do we need app timer here?"
// TODO: VERiFY IF NEEDED
/* Counter timer. */
APP_TIMER_DEF(m_timer_0);
#endif

/* Zigbee cli debug mode indicator. */
static zb_bool_t m_debug_mode = ZB_FALSE;

/* Semaphore used to block shell command handler processing. */
static K_SEM_DEFINE(zb_cmd_processed_sem, 0, 1);

LOG_MODULE_REGISTER(cli, CONFIG_ZIGBEE_CLI_LOG_LEVEL);


/**@brief Function for cli shell initial configuration.
 *        To be called by SYS_INIT.
 *
 * @param[in] unused Unused param.
 *
 * @returns By defaults returns 0.
 */
static int zb_cli_init(struct device *unused)
{
#ifdef CONFIG_ZIGBEE_SHELL_PROMPT
	zb_set_cli_default_shell_prompt(CONFIG_ZIGBEE_SHELL_PROMPT);
#endif

	return 0;
}

/**@brief Function for setting prompt for cli shell.
 *
 * @param[in] new_prompt  Pointer to new cli shell prompt.
 */
void zb_set_cli_default_shell_prompt(const char *new_prompt)
{
#ifdef CONFIG_SHELL_BACKEND_SERIAL
	if(shell_prompt_change(shell_backend_uart_get_ptr(), new_prompt)) {
		LOG_ERR("Can not change shell prompt");
	}
#endif
#ifdef CONFIG_SHELL_BACKEND_RTT
	if(shell_prompt_change(shell_backend_uart_get_ptr(), new_prompt)) {
		LOG_ERR("Can not change shell prompt");
	}
#endif
#ifdef CONFIG_SHELL_BACKEND_TELNET
	if(shell_prompt_change(shell_backend_uart_get_ptr(), new_prompt)) {
		LOG_ERR("Can not change shell prompt");
	}
#endif
}

/**@brief Mark current shell command as processed by giving semaphore.
 */
void zb_cmd_processed(void)
{
	k_sem_give(&zb_cmd_processed_sem);
}

/**@brief Blocks processing current shell command handler until all requested
 *        actions are finished, for example when getting data from other devices
 *        over Zigbee. Call `zb_cmd_processed()` when requested actions
 *        are finished.
 *
 * @param[in] timeout Specifies time to wait for requested actions
 *                    to be finished.
 */
void zb_cmd_wait_until_processed(k_timeout_t timeout)
{
	k_sem_take(&zb_cmd_processed_sem, timeout);
}

/**@brief Resets internal semaphore used to block processing shell
 *        command handlers. Call at the beginning of command handler to make
 *        sure that processing can be block properly.
 */
void zb_cmd_sem_reset(void)
{
	k_sem_reset(&zb_cmd_processed_sem);
}

/**@brief Returns the Endpoint number used by the CLI.
 */
zb_uint8_t zb_get_cli_endpoint(void)
{
	return cli_ep;
}

/**@brief Sets the Endpoint number used by the CLI.
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
	k_thread_suspend(zb_get_zboss_thread_id());
}

/**@brief Function for resuming the processing of the Zigbee main loop.
 */
zb_void_t zb_cli_resume(zb_void_t)
{
	k_thread_resume(zb_get_zboss_thread_id());
}

/**@brief Function for getting the state of the Zigbee stack
 *        processing suspension.
 */
zb_bool_t zb_cli_stack_is_suspended(zb_void_t)
{
	k_tid_t zboss_thread = zb_get_zboss_thread_id();

	if (zboss_thread) {
		if (!(zboss_thread->base.thread_state & _THREAD_SUSPENDED)) {
			return ZB_FALSE;
		}
	}
	return ZB_TRUE;
}

/* Initial configuration for CLI shell to be called after kernel start. */
SYS_INIT(zb_cli_init, POST_KERNEL, 96);
