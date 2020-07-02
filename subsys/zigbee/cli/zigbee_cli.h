/*$$$LICENCE_NORDIC_STANDARD<2018>$$$*/
#ifndef ZIGBEE_CLI_H__
#define ZIGBEE_CLI_H__

#include <stdint.h>

#include "zboss_api.h"
#include "zigbee_helpers.h"

/** @brief Name of the module used for logger messaging.
 */
#define ZIGBEE_CLI_LOG_NAME     ZIGBEE_NRF_LOG_MODULE_NAME

/**@brief Function for returning the number of the endpoint used by the CLI.
 */
zb_uint8_t zb_get_cli_endpoint(void);

/**@brief Function for initializing the Zigbee CLI subsystem that is using the CLI module.
 *
 * @param ep Number of the endpoint to be used for the CLI Agent.
 */
void zb_cli_init(uint8_t ep);

/**@brief Function for starting the Zigbee CLI subsystem that is using the CLI module.
 *
 * @note If USB is enabled, this function will enable the app_usbd module. As a result, all
 *       additional USBD classes must be added before calling this function.
 */
void zb_cli_start(void);

/**@brief Function for processing the Zigbee CLI subsystem.
 *
 * This function must be called in the main loop.
 *
 */
void zb_cli_process(void);

/**@brief Function for intercepting every frame coming to the endpoint.
 *
 * @param bufid    Reference to the ZBOSS buffer.
 */
zb_uint8_t cli_agent_ep_handler(zb_bufid_t bufid);

#if defined(ZIGBEE_CLI_DEBUG) || defined(DOXYGEN)
/**@brief Function for setting the state of the debug mode of the CLI.
 *
 * @param debug    Turns the debug mode on (ZB_TRUE) or off (ZB_FALSE).
 */
zb_void_t zb_cli_debug_set(zb_bool_t debug);
#endif

#if defined(ZIGBEE_CLI_DEBUG) || defined(DOXYGEN)
/**@brief Function for getting the state of the debug mode of the CLI.
 *
 * @retval ZB_TRUE  Debug mode is turned on.
 * @retval ZB_FALSE Debug mode is turned off.
 */
zb_bool_t zb_cli_debug_get(zb_void_t);
#endif

#if defined(ZIGBEE_CLI_DEBUG) || defined(DOXYGEN)
/**@brief Function for suspending the processing of the Zigbee main loop.
 */
zb_void_t zb_cli_suspend(zb_void_t);
#endif

#if defined(ZIGBEE_CLI_DEBUG) || defined(DOXYGEN)
/**@brief Function for resuming the processing of the Zigbee main loop.
 */
zb_void_t zb_cli_resume(zb_void_t);
#endif

#if defined(ZIGBEE_CLI_DEBUG) || defined(DOXYGEN)
/**@brief Function for getting the state of the Zigbee scheduler processing suspension.
 *
 * @retval ZB_TRUE  Scheduler processing is suspended.
 * @retval ZB_FALSE Scheduler processing is not suspended.
 */
zb_bool_t zb_cli_stack_is_suspended(zb_void_t);
#endif

/**@brief Function for checking if the Zigbee stack has been started
 *
 * @retval ZB_TRUE  Zigbee stack has been started (CLI command 'bdb start' has been executed successfully)
 * @retval ZB_FALSE Zigbee stack has not been started yet
 */
zb_bool_t zb_cli_is_stack_started(void);

#endif /* ZIGBEE_CLI_H__ */
