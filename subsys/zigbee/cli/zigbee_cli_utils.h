/*
 * Copyright (c) 2018 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZIGBEE_CLI_UTILS_H__
#define ZIGBEE_CLI_UTILS_H__

#include <stdbool.h>
#include <zephyr/types.h>
#include <shell/shell.h>

#include <zboss_api.h>
#include <zigbee_helpers.h>

/*@brief Macro which defines the Endpoint Handler section,
 *       which allows iterating over them.
 */
/* TODO: REMOVE
#define NRF_ZIGBEE_EP_HANDLER_REGISTER(desc, p_handler)           \
   NRF_SECTION_ITEM_REGISTER(zb_ep_handlers, zb_device_handler_t const CONCAT_2(zb_ep_, desc)) = p_handler;

static inline void print_usage(const struct shell *shell,
                               const char * p_command,
                               const char * p_help_string)
{
    nrf_cli_help_print(p_cli, NULL, 0);
    nrf_cli_fprintf(p_cli, NRF_CLI_NORMAL, "Usage:\r\n");
    nrf_cli_fprintf(p_cli, NRF_CLI_NORMAL, "   %s %s\r\n", p_command, p_help_string);
}
*/ //TODO: REMOVE

/**@brief Finish the command by dumping 'Done'.
 *
 * @param prepend_newline      Whether to prepend a newline.
 */
static inline void print_done(const struct shell *shell, bool prepend_newline)
{
	shell_print(shell, prepend_newline ? "\nDone" : "Done");
}

/**@brief Print error message to the console.
 *
 * @param p_message       Pointer to the message which should be printed
 *                        as an error.
 * @param prepend_newline Whether to prepend a newline.
 */
static inline void print_error(const struct shell *shell, const char *p_message,
			       bool prepend_newline)
{
	if (p_message) {
		shell_error(shell, prepend_newline ? "\nError: %s"
				: "Error: %s", p_message);
	} else {
		shell_error(shell,
			    prepend_newline ? "\nError: Unknown error occurred"
				: "Error: Unknown error occurred");
	}
}

/**@brief Print a list of items.
 *
 * Individual items in the list are delimited by comma.
 *
 * @param shell a pointer to shell instance
 * @param hdr   the list header string
 * @param fmt   a printf like format of an individual list item
 * @param type  type of the list item
 * @param size  the list size (in items)
 */
#define PRINT_LIST(shell, hdr, fmt, type, ptr, size)                       \
{                                                                          \
	shell_print(shell, hdr);                                           \
	for (type * p_item = (ptr); p_item < (ptr) + size - 1; p_item++) { \
		shell_print(shell, fmt ",", *p_item);                      \
		}                                                          \
	if (size > 0) {                                                    \
		shell_print(shell, fmt " ", *((ptr) + size - 1));          \
	}                                                                  \
}

/**@brief Convert ZCL attribute value to string.
 *
 * @param p_str_buf[out]  Pointer to a string buffer which will be filled.
 * @param buf_len[in]     String buffer length.
 * @param attr_type[in]   ZCL attribute type value.
 * @param p_attr[in]      Pointer to ZCL attribute value.
 *
 * @return number of bytes written into string bufferor negative value
 * on error.
 */
int zcl_attr_to_str(char *p_str_buf, u16_t buf_len, zb_uint16_t attr_type,
		    zb_uint8_t *p_attr);

/**@brief Parse u8_t from input string.
 *
 * The reason for this explicit function is because newlib-nano sscanf()
 * does not support 1-byte target.
 *
 * @param[in]  p_bp Pointer to input string.
 * @param[out] p_u8 Pointer to output value.
 *
 * @return 1 on success, 0 otherwise
 */
int sscan_uint8(const char * p_bp, u8_t * p_u8);

/**@brief Print buffer as hex string.
 *
 * @param shell     Pointer to shell instance.
 * @param p_in      Pointer to data to be printed out.
 * @param size      Data size in bytes
 * @param reverse   If True then data is printed out in reverse order.
 */
void print_hexdump(const struct shell *shell, const u8_t * p_in, u8_t size,
		   bool reverse);

/**@brief Print 64bit value (address, extpan) as hex string.
 *
 * The value is expected to be low endian.
 *
 * @param shell     Pointer to shell instance.
 * @param addr      64 data to be printed out.
 */
static inline void print_eui64(const struct shell *shell,
			       const zb_64bit_addr_t addr)
{
	print_hexdump(shell, (const u8_t *)addr, sizeof(zb_64bit_addr_t), true);
}

#endif /* ZIGBEE_CLI_UTILS_H__ */
