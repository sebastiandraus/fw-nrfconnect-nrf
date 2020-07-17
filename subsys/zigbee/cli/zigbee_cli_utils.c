/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <zephyr/types.h>
#include <shell/shell.h>

#include <zboss_api.h>
#include <zb_error_handler.h>
#include <zigbee_logger_eprxzcl.h>
#include "zigbee_cli_utils.h"

#ifndef DEVELOPMENT_TODO
#error "Endpoint handler to be done here"
// TODO: REMOVE
NRF_SECTION_DEF(zb_ep_handlers, zb_device_handler_t);
#define ZB_EP_HANDLER_SECTION_ITEM_GET(i) NRF_SECTION_ITEM_GET(zb_ep_handlers, zb_device_handler_t, (i))
#define ZB_EP_HANDLER_SECTION_ITEM_COUNT  NRF_SECTION_ITEM_COUNT(zb_ep_handlers, zb_device_handler_t)

zb_uint8_t cli_agent_ep_handler(zb_bufid_t bufid)
{
	unsigned int idx;

// #if defined(DEBUG_NRF) && NRF_LOG_ENABLED
	UNUSED_RETURN_VALUE(zigbee_logger_eprxzcl_ep_handler(bufid));
// #endif

	for (idx = 0; idx < ZB_EP_HANDLER_SECTION_ITEM_COUNT; idx++) {
		zb_device_handler_t handler = *(ZB_EP_HANDLER_SECTION_ITEM_GET(idx));
		if (handler(bufid) == ZB_TRUE) {
			return ZB_TRUE;
		}
	}

	return ZB_FALSE;
}
//TODO: REMOVE
#endif

int zcl_attr_to_str(char *p_str_buf, u16_t buf_len, zb_uint16_t attr_type,
		    zb_uint8_t *p_attr)
{
	int bytes_written = 0;
	int string_len;
	int i;

	if ((p_str_buf == NULL) || (p_attr == NULL)) {
		return -1;
	}

	switch (attr_type) {
	/* Boolean. */
	case ZB_ZCL_ATTR_TYPE_BOOL:
		bytes_written = snprintf(p_str_buf, buf_len, "%s",
					 *((zb_bool_t *)p_attr) ? "True"
					  : "False");
		break;

	/* 1 byte. */
	case ZB_ZCL_ATTR_TYPE_8BIT:
	case ZB_ZCL_ATTR_TYPE_8BITMAP:
	case ZB_ZCL_ATTR_TYPE_U8:
	case ZB_ZCL_ATTR_TYPE_8BIT_ENUM:
		bytes_written = snprintf(p_str_buf, buf_len, "%hu",
					 *((zb_uint8_t*)p_attr));
		break;

	case ZB_ZCL_ATTR_TYPE_S8:
		bytes_written = snprintf(p_str_buf, buf_len, "%hd",
					 *((zb_int8_t*)p_attr));
		break;

	/* 2 bytes. */
	case ZB_ZCL_ATTR_TYPE_16BIT:
	case ZB_ZCL_ATTR_TYPE_16BITMAP:
	case ZB_ZCL_ATTR_TYPE_U16:
	case ZB_ZCL_ATTR_TYPE_16BIT_ENUM:
		bytes_written = snprintf(p_str_buf, buf_len, "%hu",
					 *((zb_uint16_t*)p_attr));
		break;

	case ZB_ZCL_ATTR_TYPE_S16:
		bytes_written = snprintf(p_str_buf, buf_len, "%hd",
					 *((zb_int16_t*)p_attr));
		break;

	/* 4 bytes. */
	case ZB_ZCL_ATTR_TYPE_32BIT:
	case ZB_ZCL_ATTR_TYPE_32BITMAP:
	case ZB_ZCL_ATTR_TYPE_U32:
		bytes_written = snprintf(p_str_buf, buf_len, "%u",
					 *((zb_uint32_t*)p_attr));
		break;

	case ZB_ZCL_ATTR_TYPE_S32:
		bytes_written = snprintf(p_str_buf, buf_len, "%d",
					 *((zb_int32_t*)p_attr));
		break;

	/* String. */
	case ZB_ZCL_ATTR_TYPE_CHAR_STRING:
		string_len = p_attr[0];
		p_attr++;

		if ((buf_len - bytes_written) < (string_len + 1)) {
			return -1;
		}

		for (i = 0; i < string_len; i++) {
			p_str_buf[bytes_written + i] = ((char *)p_attr)[i];
		}
		p_str_buf[bytes_written + i] = '\0';
		bytes_written += string_len + 1;
		break;

	case ZB_ZCL_ATTR_TYPE_IEEE_ADDR:
		bytes_written = to_hex_str(p_str_buf, buf_len,
					   (const u8_t *)p_attr,
					   sizeof(zb_64bit_addr_t), true);
		break;

	default:
		bytes_written = snprintf(p_str_buf, buf_len,
					 "Value type 0x%x unsupported",
					 attr_type);
		break;
	}

	return bytes_written;
}

int sscan_uint8(const char *p_bp, u8_t *p_u8)
{
	/* strtoul() used as a replacement for lacking sscanf(),
	 * first character is tested to make sure that is a digit.
	 */
	char *p_end = NULL;
	unsigned long value;
	value = strtoul(p_bp, &p_end, 10);

	if (((value == 0) && (p_bp == p_end)) || (value > UINT8_MAX)) {
		return 0;
	}

	*p_u8 = value & 0xFF;

	return 1;
}

int sscan_uint(const char *p_bp, u8_t *p_value, u8_t size, u8_t base)
{
	char *p_end = NULL;
	long unsigned int value;

	value = strtoul(p_bp, &p_end, base);

	/* Validation steps:
	 *   - check if returned value is not zero - strtoul returns zero
	 *     if failed to convert string.
	 *   - check if p_end is not equal p_bp - p_end is set to point
	 *     to the first character after the number or to p_pb
	 *     if nothing is matched.
	 *   - check if returned value can be stored in variable of length
	 *     given by `size` argument.
	 */
	if ((value == 0) && (p_bp == p_end)) {
		return 0;
	}
	if (size == 4) {
		*((u32_t*)p_value) = value & ((1 << (size * 8)) - 1);
	} else if (size == 2) {
		*((u16_t*)p_value) = value & ((1 << (size * 8)) - 1);
	} else {
		*p_value = value & ((1 << (size * 8)) - 1);
	}

	return 1;
}

void print_hexdump(const struct shell *shell, const u8_t *p_in, u8_t size,
		   bool reverse)
{
	char addr_buf[2 * size + 1];
	int bytes_written = 0;

	memset(addr_buf, 0, sizeof(addr_buf));

	bytes_written = to_hex_str(addr_buf, (u16_t)sizeof(addr_buf), p_in,
				   size, reverse);
	if (bytes_written < 0) {
		shell_fprintf(shell, SHELL_ERROR, "%s", "Unable to print hexdump");
	} else {
		shell_fprintf(shell, SHELL_NORMAL, "%s", addr_buf);
	}
}
