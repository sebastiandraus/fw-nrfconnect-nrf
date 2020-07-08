/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
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
#ifndef DEVELOPMENT_TODO
// TODO: REMOVE
#error "Endpoint to be defined here"
#define NRF_ZIGBEE_EP_HANDLER_REGISTER(desc, p_handler)           \
   NRF_SECTION_ITEM_REGISTER(zb_ep_handlers, zb_device_handler_t const CONCAT_2(zb_ep_, desc)) = p_handler;
*/ //TODO: REMOVE
#endif

/**@brief Finish the command by dumping 'Done'.
 *
 * @param prepend_newline      Whether to prepend a newline.
 */
static inline void print_done(const struct shell *shell, bool prepend_newline)
{
	shell_fprintf(shell, SHELL_NORMAL,
		      prepend_newline ? "\nDone\n" : "Done\n");
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
		shell_fprintf(shell, SHELL_ERROR, prepend_newline ?
			      "\nError: %s\n" : "Error: %s\n", p_message);
	} else {
		shell_fprintf(shell, SHELL_ERROR, prepend_newline ?
			      "\nError: Unknown error occurred\n" :
			      "Error: Unknown error occurred\n");
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
	shell_fprintf(shell, SHELL_NORMAL, hdr);                           \
	for (type * p_item = (ptr); p_item < (ptr) + size - 1; p_item++) { \
		shell_fprintf(shell, SHELL_NORMAL, fmt ",", *p_item);      \
		}                                                          \
	if (size > 0) {                                                    \
		shell_fprintf(shell, SHELL_NORMAL, fmt " ",                \
		              *((ptr) + size - 1));                        \
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
 * @return 1 on success, 0 otherwise.
 */
int sscan_uint8(const char * p_bp, u8_t * p_u8);

/**@brief Parse unsigned integers from input string.
 *
 * The reason for this explicit function is because of lack
 * of sscanf() function. This function is to be used to parse number
 * up to (UINT32_MAX).
 *
 * @param[in]  p_bp    Pointer to input string.
 * @param[out] p_value Pointer to variable to store reuslt of the function.
 * @param[in]  size    Size, in bytes, that determines expected maximum value
 *                     of converted number.
 * @param[in]  base    Numerical base (radix) that determines the valid
 *                     characters and their interpretation.
 *
 * @return 1 on success, 0 otherwise.
 */
int sscan_uint(const char *p_bp, u8_t *p_value, u8_t size, u8_t base);

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
