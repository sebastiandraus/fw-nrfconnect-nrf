/*$$$LICENCE_NORDIC_STANDARD<2018>$$$*/
#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include "zigbee_cli.h"

/* CLI Agent endpoint */
static zb_uint8_t cli_ep;

/* Counter timer. */
APP_TIMER_DEF(m_timer_0);

#ifdef ZIGBEE_CLI_DEBUG
/* Debug mode indicator. */
static zb_bool_t m_debug_mode = ZB_FALSE;
#endif

#ifdef ZIGBEE_CLI_DEBUG
/* Zigbee stack processing suspension indicator. */
static zb_bool_t m_suspended = ZB_FALSE;
#endif

/**@brief Returns the number of the Endpoint used by the CLI.
 */
zb_uint8_t zb_get_cli_endpoint(void)
{
    return cli_ep;
}

#ifdef ZIGBEE_CLI_DEBUG
/**@brief Sets the debug mode.
 */
zb_void_t zb_cli_debug_set(zb_bool_t debug)
{
    m_debug_mode = debug;
}
#endif

#ifdef ZIGBEE_CLI_DEBUG
/**@brief Gets the debug mode.
 */
zb_bool_t zb_cli_debug_get(zb_void_t)
{
    return m_debug_mode;
}
#endif

#ifdef ZIGBEE_CLI_DEBUG
/**@brief Function for suspending the processing of the Zigbee main loop.
 */
zb_void_t zb_cli_suspend(zb_void_t)
{
    m_suspended = ZB_TRUE;
}
#endif

#ifdef ZIGBEE_CLI_DEBUG
/**@brief Function for resuming the processing of the Zigbee main loop.
 */
zb_void_t zb_cli_resume(zb_void_t)
{
    m_suspended = ZB_FALSE;
}
#endif

#ifdef ZIGBEE_CLI_DEBUG
/**@brief Function for getting the state of the Zigbee stack processing suspension.
 */
zb_bool_t zb_cli_stack_is_suspended(zb_void_t)
{
    return m_suspended;
}
#endif

/** @} */
