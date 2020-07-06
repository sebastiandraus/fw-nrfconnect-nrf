/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZIGBEE_CLI_CMD_ZCL_H__
#define ZIGBEE_CLI_CMD_ZCL_H__

int cmd_zb_ping(const struct shell *shell, size_t argc, char **argv);
int cmd_zb_readattr(const struct shell *shell, size_t argc, char **argv);
int cmd_zb_writeattr(const struct shell *shell, size_t argc, char **argv);
int cmd_zb_subscribe(const struct shell *shell, size_t argc, char **argv);
int cmd_zb_generic_cmd(const struct shell *shell, size_t argc, char **argv);
int cmd_zb_zcl_raw(const struct shell *shell, size_t argc, char **argv);

#endif /* ZIGBEE_CLI_CMD_ZCL_H__ */
