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
#include <shell/shell_rtt.h>

#include <zb_nrf_platform.h>
#include "zigbee_cli.h"

/* CLI Agent endpoint, by default set to greatest endpoint number. */
static zb_uint8_t cli_ep = ZB_MAX_ENDPOINT_NUMBER;

/* Zigbee cli debug mode indicator. */
static zb_bool_t m_debug_mode = ZB_FALSE;

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
	if(shell_prompt_change(shell_backend_rtt_get_ptr(), new_prompt)) {
		LOG_ERR("Can not change shell prompt");
	}
#endif
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

/**@brief Scans ZCL context to find endpoint which can be used to send
 *        ZCL frames. By default tries to find the lowest number endpoint.
 */
zb_void_t zb_set_default_cli_endpoint(zb_void_t)
{
	/* Set to maximum endpoint number. */
	zb_uint8_t ep_to_set = ZB_MAX_ENDPOINT_NUMBER;
	zb_zcl_globals_t *p_zcl_ctx = zb_zcl_get_ctx();

	/* Check if cli endpoint has been changed and if not, set default value
	 * of cli endpoint.
	 */
	if (zb_get_cli_endpoint() != ep_to_set) {
		return;
	}

	/* Verify that ZCL device ctx is present at the device as for example,
	 * network coordinator sample doesn't have one by default.
	 */
	if (p_zcl_ctx->device_ctx == NULL) {
		return;
	}

	/* Iterate over all endpoints present in ZCL ctx to find
	 * endpoint with lowest number.
	 */
	for (u8_t index = 0; index < p_zcl_ctx->device_ctx->ep_count; index++) {
		zb_uint8_t temp_ep =
			p_zcl_ctx->device_ctx->ep_desc_list[index]->ep_id;
		/* Validate endpoint number:
		 * - not a ZDO endpoint (temp_ep != 0)
		 * - not a reserved value (temp_ep < 241)
		 */
		if ((temp_ep < ZB_MIN_ENDPOINT_NUMBER) ||
		    (temp_ep > ZB_MAX_ENDPOINT_NUMBER)) {
			continue;
		}
		if (temp_ep < ep_to_set) {
			ep_to_set = temp_ep;
		}
	}
	if (ep_to_set != ZB_MAX_ENDPOINT_NUMBER) {
		zb_set_cli_endpoint(ep_to_set);
	}
}

/**@brief Sets CLI agent as endpoint handler if a endpoint handler hasn't been
 *        yet set for endpoint used by the CLI.
 */
zb_void_t zb_set_default_cli_endpoint_handler(void)
{
	zb_uint8_t cli_ep = zb_get_cli_endpoint();
	zb_af_endpoint_desc_t *cli_ep_desc;

	/* Verify that ZCL device ctx is present at the device as for example,
	 * network coordinator sample doesn't have one by default.
	 */
	if (zb_zcl_get_ctx()->device_ctx == NULL) {
		return;
	}

	cli_ep_desc = zb_af_get_endpoint_desc(cli_ep);

	if ((cli_ep == ZB_MAX_ENDPOINT_NUMBER) || (cli_ep_desc == NULL)) {
		return;
	}

	if (!cli_ep_desc->device_handler) {
		ZB_AF_SET_ENDPOINT_HANDLER(cli_ep, cli_agent_ep_handler);
	}
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
