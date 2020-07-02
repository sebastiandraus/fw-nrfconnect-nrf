/*$$$LICENCE_NORDIC_STANDARD<2018>$$$*/
#include "zboss_api.h"
#include "zb_error_handler.h"
#include "zb_version.h"
#include "zigbee_cli.h"
#include "zigbee_cli_utils.h"


/**@brief Print CLI and ZBOSS version
 *
 * @code
 * version
 * @endcode
 *
 * @code
 * > version
 * CLI: Dec 11 2018 16:14:18
 * ZBOSS: 3.1.0.59
 * Done
 * @endcode
 */
static void cmd_version(nrf_cli_t const * p_cli, size_t argc, char **argv)
{
    if (nrf_cli_help_requested(p_cli))
    {
        nrf_cli_help_print(p_cli, NULL, 0);
        return;
    }

    nrf_cli_fprintf(p_cli, NRF_CLI_NORMAL, "CLI: " __DATE__ " " __TIME__ "\r\n");
    nrf_cli_fprintf(p_cli, NRF_CLI_NORMAL, "ZBOSS: %d.%d.0.%d \r\n",
                    ZBOSS_MAJOR, ZBOSS_MINOR, ZBOSS_SDK_REVISION);
    print_done(p_cli, ZB_FALSE);
}

/**@brief Perform device reset using NVIC_SystemReset().
 *
 * @code
 * > reset
 * @endcode
 */
static void cmd_reset(nrf_cli_t const * p_cli, size_t argc, char **argv)
{

    UNUSED_PARAMETER(argc);
    UNUSED_PARAMETER(argv);

    if (nrf_cli_help_requested(p_cli))
    {
        nrf_cli_help_print(p_cli, NULL, 0);
        return;
    }

    NVIC_SystemReset();
}

#ifdef ZIGBEE_CLI_DEBUG
/**@brief Enable/Disable debug mode in the CLI
 *
 * @code
 * debug <on|off>
 * @endcode
 *
 * This command unblocks several additional commands in the CLI.
 * They can render the device unstable. It is implied that you know what you are doing.
 */
static void cmd_debug(nrf_cli_t const * p_cli, size_t argc, char **argv)
{
    if (nrf_cli_help_requested(p_cli))
    {
        nrf_cli_help_print(p_cli, NULL, 0);
        return;
    }

    if (argc == 1)
    {
        if (zb_cli_debug_get() == ZB_TRUE)
        {
            nrf_cli_fprintf(p_cli, NRF_CLI_NORMAL, "Debug mode is on.");
        }
        else
        {
            nrf_cli_fprintf(p_cli, NRF_CLI_NORMAL, "Debug mode is off.");
        }

        print_done(p_cli, ZB_TRUE);
        return;
    }

    if (argc != 2)
    {
        print_error(p_cli, "Invalid number of arguments", ZB_FALSE);
        return;
    }

    if (!strcmp(argv[1], "on"))
    {
        nrf_cli_fprintf(p_cli, NRF_CLI_WARNING, "You are about to turn the debug mode on. This unblocks several additional commands in the CLI.\n");
        nrf_cli_fprintf(p_cli, NRF_CLI_WARNING, "They can render the device unstable. It is implied that you know what you are doing.\n");
        zb_cli_debug_set(ZB_TRUE);
        nrf_cli_fprintf(p_cli, NRF_CLI_NORMAL, "Debug mode is on.");
    }
    else if (!strcmp(argv[1], "off"))
    {
        zb_cli_debug_set(ZB_FALSE);
        nrf_cli_fprintf(p_cli, NRF_CLI_NORMAL, "Debug mode is off.");
    }
    else
    {
        print_error(p_cli, "Unrecognized argument", ZB_FALSE);
        return;
    }
    print_done(p_cli, ZB_TRUE);
}
#endif /* ZIGBEE_CLI_DEBUG */

NRF_CLI_CMD_REGISTER(version, NULL, "Firmware version", cmd_version);
NRF_CLI_CMD_REGISTER(reset, NULL, "Reset", cmd_reset);
#ifdef ZIGBEE_CLI_DEBUG
NRF_CLI_CMD_REGISTER(debug, NULL, "Debug mode", cmd_debug);
#endif

/** @} */
