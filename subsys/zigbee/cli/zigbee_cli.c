/*
 * Copyright (c) 2018 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <shell/shell.h>

#include "zigbee_cli.h"

/* CLI Agent endpoint */
static zb_uint8_t cli_ep;

// /* Counter timer. */
// APP_TIMER_DEF(m_timer_0);

#ifdef CONFIG_ZIGBEE_SHELL_DEBUG_CMD
/* Debug mode indicator. */
static zb_bool_t m_debug_mode = ZB_FALSE;
#endif

#ifdef CONFIG_ZIGBEE_SHELL_DEBUG_CMD
/* Zigbee stack processing suspension indicator. */
static zb_bool_t m_suspended = ZB_FALSE;
#endif

/**@brief Returns the number of the Endpoint used by the CLI.
 */
zb_uint8_t zb_get_cli_endpoint(void)
{
	return cli_ep;
}

#ifdef CONFIG_ZIGBEE_SHELL_DEBUG_CMD
/**@brief Sets the debug mode.
 */
zb_void_t zb_cli_debug_set(zb_bool_t debug)
{
	m_debug_mode = debug;
}
#endif

#ifdef CONFIG_ZIGBEE_SHELL_DEBUG_CMD
/**@brief Gets the debug mode.
 */
zb_bool_t zb_cli_debug_get(zb_void_t)
{
	return m_debug_mode;
}
#endif

#ifdef CONFIG_ZIGBEE_SHELL_DEBUG_CMD
/**@brief Function for suspending the processing of the Zigbee main loop.
 */
zb_void_t zb_cli_suspend(zb_void_t)
{
	m_suspended = ZB_TRUE;
}
#endif

#ifdef CONFIG_ZIGBEE_SHELL_DEBUG_CMD
/**@brief Function for resuming the processing of the Zigbee main loop.
 */
zb_void_t zb_cli_resume(zb_void_t)
{
	m_suspended = ZB_FALSE;
}
#endif

#ifdef CONFIG_ZIGBEE_SHELL_DEBUG_CMD
/**@brief Function for getting the state of the Zigbee stack
 *        processing suspension.
 */
zb_bool_t zb_cli_stack_is_suspended(zb_void_t)
{
	return m_suspended;
}
#endif
