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


/**@brief Function for setting prompt for cli shell.
 *
 * @param[in] new_prompt  Pointer to new cli shell prompt.
 */
void zb_set_cli_default_shell_prompt(const char *new_prompt);

/**@brief Mark current shell command as processed by giving semaphore.
 */
void zb_cmd_processed(void);

/**@brief Blocks processing current shell command handler until all requested
 *        actions are finished, for example when getting data from other devices
 *        over Zigbee. Call `zb_cmd_processed()` when requested actions
 *        are finished.
 *
 * @param[in] timeout Specifies time to wait for requested actions
 *                    to be finished.
 */
void zb_cmd_wait_until_processed(k_timeout_t timeout);

/**@brief Resets internal semaphore used to block processing shell
 *        command handlers. Call at the beginning of command handler to make
 *        sure that processing can be block properly.
 */
void zb_cmd_sem_reset(void);

/**@brief Returns the Endpoint number used by the CLI.
 */
zb_uint8_t zb_get_cli_endpoint(void);

/**@brief Sets the Endpoint number used by the CLI.
 */
zb_void_t zb_set_cli_endpoint(zb_uint8_t ep);

/**@brief Scans ZCL context to find endpoint which can be used to send
 *        ZCL frames. By default tries to find the lowest number endpoint.
 */
zb_void_t zb_set_default_cli_endpoint(zb_void_t);

/**@brief Function for intercepting every frame coming to the endpoint.
 *
 * @param bufid    Reference to the ZBOSS buffer.
 */
zb_uint8_t cli_agent_ep_handler(zb_bufid_t bufid);

/**@brief Sets CLI agent as endpoint handler if a endpoint handler hasn't been
 *        yet set for endpoint used by the CLI.
 */
zb_void_t zb_set_default_cli_endpoint_handler(void);

/**@brief Function for setting the state of the debug mode of the CLI.
 *
 * @param debug    Turns the debug mode on (ZB_TRUE) or off (ZB_FALSE).
 */
zb_void_t zb_cli_debug_set(zb_bool_t debug);

/**@brief Function for getting the state of the debug mode of the CLI.
 *
 * @retval ZB_TRUE  Debug mode is turned on.
 * @retval ZB_FALSE Debug mode is turned off.
 */
zb_bool_t zb_cli_debug_get(zb_void_t);

/**@brief Function for suspending the processing of the Zigbee main loop.
 */
zb_void_t zb_cli_suspend(zb_void_t);

/**@brief Function for resuming the processing of the Zigbee main loop.
 */
zb_void_t zb_cli_resume(zb_void_t);

/**@brief Function for getting the state of the Zigbee scheduler
 *        processing suspension.
 *
 * @retval ZB_TRUE  Scheduler processing is suspended or zboss thread
 *                  is not yet created.
 * @retval ZB_FALSE Scheduler processing is not suspended and zboss thread
 *                  is created,.
 */
zb_bool_t zb_cli_stack_is_suspended(zb_void_t);

/**@brief Function for checking if the Zigbee stack has been started
 *
 * @retval ZB_TRUE  Zigbee stack has been started (CLI command 'bdb start'
 *                  has been executed successfully)
 * @retval ZB_FALSE Zigbee stack has not been started yet
 */
zb_bool_t zb_cli_is_stack_started(void);

/**@brief Function to be called when Zigbee stack is started,
 *        sets internal flag.
 */
zb_void_t zb_cli_set_stack_as_started(void);

#endif /* ZIGBEE_CLI_H__ */
