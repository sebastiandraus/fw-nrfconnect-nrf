/*$$$LICENCE_NORDIC_STANDARD<2018>$$$*/
#ifndef ZIGBEE_CLI_CMD_ZCL_H__
#define ZIGBEE_CLI_CMD_ZCL_H__

void cmd_zb_ping(nrf_cli_t const * p_cli, size_t argc, char **argv);
void cmd_zb_readattr(nrf_cli_t const * p_cli, size_t argc, char **argv);
void cmd_zb_writeattr(nrf_cli_t const * p_cli, size_t argc, char **argv);
void cmd_zb_subscribe(nrf_cli_t const * p_cli, size_t argc, char **argv);
void cmd_zb_generic_cmd(nrf_cli_t const * p_cli, size_t argc, char **argv);
void cmd_zb_zcl_raw(nrf_cli_t const * p_cli, size_t argc, char **argv);


#endif /* ZIGBEE_CLI_CMD_ZCL_H__ */
