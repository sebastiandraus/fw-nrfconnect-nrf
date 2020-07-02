/*$$$LICENCE_NORDIC_STANDARD<2018>$$$*/
#include "nrf_cli.h"
#include "zboss_api.h"
#include "zigbee_cli.h"
#include "zigbee_cli_utils.h"

/**@brief Command set array
 */


#ifdef ZIGBEE_CLI_DEBUG
/**@brief Suspend Zigbee scheduler processing
 *
 * @code
 * zscheduler suspend
 * @endcode
 *
 */
static void cmd_zb_suspend(nrf_cli_t const * p_cli, size_t argc, char **argv)
{
    if (nrf_cli_help_requested(p_cli))
    {
        nrf_cli_help_print(p_cli, NULL, 0);
        return;
    }

    if (argc != 1)
    {
        print_error(p_cli, "Invalid number of arguments", ZB_FALSE);
        return;
    }

    zb_cli_suspend();
    print_done(p_cli, ZB_TRUE);
}


/**@brief Resume Zigbee scheduler processing
 *
 * @code
 * zscheduler resume
 * @endcode
 *
 */
static void cmd_zb_resume(nrf_cli_t const * p_cli, size_t argc, char **argv)
{
    if (nrf_cli_help_requested(p_cli))
    {
        nrf_cli_help_print(p_cli, NULL, 0);
        return;
    }

    if (argc != 1)
    {
        print_error(p_cli, "Invalid number of arguments", ZB_FALSE);
        return;
    }

    zb_cli_resume();
    print_done(p_cli, ZB_TRUE);
}


NRF_CLI_CREATE_STATIC_SUBCMD_SET(m_sub_zigbee)
{
    NRF_CLI_CMD(suspend, NULL, "suspend Zigbee scheduler processing", cmd_zb_suspend),
    NRF_CLI_CMD(resume, NULL, "suspend Zigbee scheduler processing", cmd_zb_resume),
    NRF_CLI_SUBCMD_SET_END
};

NRF_CLI_CMD_REGISTER(zscheduler, &m_sub_zigbee, "Zigbee scheduler manipulation", NULL);
#endif
