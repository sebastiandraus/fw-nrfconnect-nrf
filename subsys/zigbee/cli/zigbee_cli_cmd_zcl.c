/*$$$LICENCE_NORDIC_STANDARD<2018>$$$*/
#include "nrf_cli.h"
#include "zboss_api.h"
#include "zb_error_handler.h"
#include "zigbee_cli.h"
#include "zigbee_cli_cmd_zcl.h"

/**@brief Command set array
 */

NRF_CLI_CREATE_STATIC_SUBCMD_SET(m_sub_attr)
{
    NRF_CLI_CMD(read, NULL, "read attribute", cmd_zb_readattr),
    NRF_CLI_CMD(write, NULL, "write attribute", cmd_zb_writeattr),
    NRF_CLI_SUBCMD_SET_END
};

NRF_CLI_CREATE_STATIC_SUBCMD_SET(m_sub_subscribe)
{
    NRF_CLI_CMD(on, NULL, "subscribe to", cmd_zb_subscribe),
    NRF_CLI_CMD(off, NULL, "unsubscribe from", cmd_zb_subscribe),
    NRF_CLI_SUBCMD_SET_END
};

NRF_CLI_CREATE_STATIC_SUBCMD_SET(m_sub_zcl)
{
    NRF_CLI_CMD(attr, &m_sub_attr, "read/write attribute", NULL),
    NRF_CLI_CMD(ping, NULL, "ping over ZCL", cmd_zb_ping),
    NRF_CLI_CMD(subscribe, &m_sub_subscribe, "(un)subscribe to an attribute", NULL),
    NRF_CLI_CMD(cmd, NULL, "send generic command", cmd_zb_generic_cmd),
#ifdef ZIGBEE_CLI_DEBUG
    NRF_CLI_CMD(raw, NULL, "send raw ZCL frame", cmd_zb_zcl_raw),
#endif
    NRF_CLI_SUBCMD_SET_END
};

NRF_CLI_CMD_REGISTER(zcl, &m_sub_zcl, "ZCL manipulation", NULL);
