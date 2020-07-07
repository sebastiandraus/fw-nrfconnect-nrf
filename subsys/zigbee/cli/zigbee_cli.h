/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZIGBEE_CLI_H__
#define ZIGBEE_CLI_H__

#include <stdint.h>

#include <zboss_api.h>
#include <zigbee_helpers.h>

void zb_cli_init(void);

void zb_set_cli_shell_prompt(const char *new_prompt);

/**@brief Function for returning the number of the endpoint used by the CLI.
 */
zb_uint8_t zb_get_cli_endpoint(void);

/**@brief Sets the number of the Endpoint used by the CLI.
 */
zb_void_t zb_set_cli_endpoint(zb_uint8_t ep);

/**@brief Function for intercepting every frame coming to the endpoint.
 *
 * @param bufid    Reference to the ZBOSS buffer.
 */
zb_uint8_t cli_agent_ep_handler(zb_bufid_t bufid);

#if defined(CONFIG_ZIGBEE_SHELL_DEBUG_CMD)
/**@brief Function for setting the state of the debug mode of the CLI.
 *
 * @param debug    Turns the debug mode on (ZB_TRUE) or off (ZB_FALSE).
 */
zb_void_t zb_cli_debug_set(zb_bool_t debug);
#endif

#if defined(CONFIG_ZIGBEE_SHELL_DEBUG_CMD)
/**@brief Function for getting the state of the debug mode of the CLI.
 *
 * @retval ZB_TRUE  Debug mode is turned on.
 * @retval ZB_FALSE Debug mode is turned off.
 */
zb_bool_t zb_cli_debug_get(zb_void_t);
#endif

#if defined(CONFIG_ZIGBEE_SHELL_DEBUG_CMD)
/**@brief Function for suspending the processing of the Zigbee main loop.
 */
zb_void_t zb_cli_suspend(zb_void_t);
#endif

#if defined(CONFIG_ZIGBEE_SHELL_DEBUG_CMD)
/**@brief Function for resuming the processing of the Zigbee main loop.
 */
zb_void_t zb_cli_resume(zb_void_t);
#endif

#if defined(CONFIG_ZIGBEE_SHELL_DEBUG_CMD)
/**@brief Function for getting the state of the Zigbee scheduler
 *        processing suspension.
 *
 * @retval ZB_TRUE  Scheduler processing is suspended.
 * @retval ZB_FALSE Scheduler processing is not suspended.
 */
zb_bool_t zb_cli_stack_is_suspended(zb_void_t);
#endif

/**@brief Function for checking if the Zigbee stack has been started
 *
 * @retval ZB_TRUE  Zigbee stack has been started (CLI command 'bdb start'
 *                  has been executed successfully)
 * @retval ZB_FALSE Zigbee stack has not been started yet
 */
zb_bool_t zb_cli_is_stack_started(void);

#endif /* ZIGBEE_CLI_H__ */
