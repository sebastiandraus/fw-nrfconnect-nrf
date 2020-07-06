/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <shell/shell.h>

#include <zboss_api.h>
#include <zb_error_handler.h>
#include "zigbee_cli.h"
#include "zigbee_cli_cmd_zcl.h"

#define ATTR_READ_HELP \
	("Sends Read Attribute Zigbee command.\n" \
	" Usage: read <h:dst_addr> <d:ep> <h:cluster>" \
		" [-c] <h:profile> <h:attr_id>\n" \
	" -c switches the server-to-client direction.\n" \
	" h: is for hex, d: is for decimal.")

#define ATTR_WRITE_HELP \
	("Sends Write Attribute Zigbee command.\n" \
	" Usage: write <h:dst_addr> <d:ep> <h:cluster> [-c] <h:profile>" \
	"<h:attr_id> <h:attr_type> <h:attr_value>\n" \
	" -c switches the server-to-client direction.\n" \
	" h: is for hex, d: is for decimal.")

#define SUBSCRIBE_HELP "(un)subscribe to an attribute"

#define SUBSCRIBE_ON_HELP \
	("Subscribes to an attribute.\n" \
	" Usage: on <h:addr> <d:ep> <h:cluster>" \
	" <h:profile> <h:attr_id> <d:attr_type>" \
	" [<d:min_interval (s)>] [<d:max_interval (s)>]")

#define SUBSCRIBE_OFF_HELP \
	("Unubscribes from an attribute.\n" \
	" Usage: off <h:addr> <d:ep> <h:cluster>" \
	" <h:profile> <h:attr_id> <d:attr_type>")

#define PING_HELP \
	("Sends ping command over ZCL.\n" \
	" Usage: ping [--no-echo] [--aps-ack] <h:addr> <d:payload size>")

/**@brief Command set array
 */
SHELL_STATIC_SUBCMD_SET_CREATE(sub_attr,
	SHELL_CMD_ARG(read, NULL, ATTR_READ_HELP, cmd_zb_readattr, 6, 1),
	SHELL_CMD_ARG(write, NULL, ATTR_WRITE_HELP, cmd_zb_writeattr, 8, 1),
	SHELL_SUBCMD_SET_END);

SHELL_STATIC_SUBCMD_SET_CREATE(sub_subsbcribe,
	SHELL_CMD_ARG(on, NULL, SUBSCRIBE_ON_HELP, cmd_zb_subscribe, 7, 2),
	SHELL_CMD_ARG(off, NULL, SUBSCRIBE_OFF_HELP, cmd_zb_subscribe, 7, 0),
	SHELL_SUBCMD_SET_END);

SHELL_STATIC_SUBCMD_SET_CREATE(sub_zcl,
	SHELL_CMD(attr, &sub_attr, "read/write attribute", NULL),
	SHELL_CMD_ARG(ping, NULL, PING_HELP, cmd_zb_ping, 3, 2),
	SHELL_CMD(subscribe, &sub_subsbcribe, SUBSCRIBE_HELP, NULL),
	SHELL_SUBCMD_SET_END);

SHELL_CMD_REGISTER(zcl, &sub_zcl, "zcl subsystem commands", NULL);

// NRF_CLI_CREATE_STATIC_SUBCMD_SET(m_sub_zcl)
// {
//     NRF_CLI_CMD(attr, &m_sub_attr, "read/write attribute", NULL),
//     NRF_CLI_CMD(ping, NULL, "ping over ZCL", cmd_zb_ping),
//     NRF_CLI_CMD(subscribe, &m_sub_subscribe, "(un)subscribe to an attribute", NULL),
//     NRF_CLI_CMD(cmd, NULL, "send generic command", cmd_zb_generic_cmd),
// #ifdef CONFIG_ZIGBEE_SHELL_DEBUG_CMD
//     NRF_CLI_CMD(raw, NULL, "send raw ZCL frame", cmd_zb_zcl_raw),
// #endif
//     NRF_CLI_SUBCMD_SET_END
// };
