/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <shell/shell.h>

#include <zboss_api.h>
#include <zb_error_handler.h>
#include <zb_nrf_platform.h>
#include "zigbee_cli.h"
#include "zigbee_cli_utils.h"
#include "zigbee_cli_cmd_zcl.h"

#define ATTRIBUTE_TABLE_SIZE     20
#define ATTRIBUTE_ROW_TIMEOUT_S  10

typedef enum attr_type_e {
	ATTR_READ_REQUEST,
	ATTR_WRITE_REQUEST
} attr_req_type_t;

/**@brief The row of the table which holds the requests which were sent.
 *
 * @details We compare the incoming responses with the rows contents
 *          to determine if it is the answer. The structure corresponds to both
 *          read and write requests.
 *          The key parameter is the sequence number.
 */
typedef struct attr_query_s {
	atomic_t                   taken;
	zb_uint8_t                 seq_num;
	attr_req_type_t            req_type;
	zb_uint16_t                profile_id;
	zb_uint16_t                cluster_id;
	zb_uint16_t                attr_id;
	zb_uint8_t                 attr_type;
	zb_uint8_t                 attr_value[32];
	zb_zcl_frame_direction_t   direction;
	const struct shell         *shell;
	zcl_packet_info_t          packet_info;
} attr_query_t;

static attr_query_t m_attr_table[ATTRIBUTE_TABLE_SIZE];

/**@brief Get the first free row in the attributes table, return -1 if none.
 */
static zb_int8_t get_free_row_attr_table()
{
	int i;
	for (i = 0; i < ATTRIBUTE_TABLE_SIZE; i++) {
		if (atomic_get(&m_attr_table[i].taken) == ZB_FALSE) {
			return i;
		}
	}
	return -1;
}

/**@brief Get the taken row with the selected seq_num, return -1 if none.
 *
 * @param sernum Sequence Number to look for.
 */
static zb_int8_t get_attr_table_row_by_sn(zb_uint8_t sernum)
{
	int i;
	for (i = 0; i < ATTRIBUTE_TABLE_SIZE; i++) {
		if (atomic_get(&m_attr_table[i].taken) == ZB_TRUE) {
			if (m_attr_table[i].seq_num == sernum) {
				return i;
			}
		}
	}
	return -1;
}

/**@brief Invalidate row after the timeout.
 *
 * @param row     Number of row to invalidate.
 */
static zb_void_t invalidate_row(zb_uint8_t row)
{
	if (row < ATTRIBUTE_TABLE_SIZE) {
		atomic_set(&m_attr_table[row].taken, ZB_FALSE);
		ZB_MEMSET(&(m_attr_table[row]), 0x00, sizeof(attr_query_t));
	}
}
/**@brief Invalidate row after the timeout - ZBOSS callback.
 *
 * @param row     Number of row to invalidate.
 */
static zb_void_t invalidate_row_cb(zb_uint8_t row)
{
	print_error(m_attr_table[row].shell, "Request timed out", ZB_FALSE);
	invalidate_row(row);
}

static zb_void_t frame_acked_cb(zb_bufid_t bufid)
{
	if (bufid) {
		zb_buf_free(bufid);
	}
}

/**@brief Check if the frame we received is the response to our request
 *        in the table.
 *
 * @param p_hdr  Pointer to the parsed header of the frame.
 * @param p_row  Pointer to the row in the table to check against.
 *
 * @return Whether it is response or not.
 */
static zb_bool_t is_response(zb_zcl_parsed_hdr_t * p_hdr, attr_query_t * p_row)
{
	zb_uint16_t remote_node_short = 0;
	if (p_row->packet_info.dst_addr_mode ==
	    ZB_APS_ADDR_MODE_64_ENDP_PRESENT) {
		remote_node_short = zb_address_short_by_ieee(
					p_row->packet_info.dst_addr.addr_long);
	} else {
		remote_node_short = p_row->packet_info.dst_addr.addr_short;
	}

	if (p_hdr->cluster_id != p_row->cluster_id) {
		return ZB_FALSE;
	}

	if (p_hdr->profile_id != p_row->profile_id) {
		return ZB_FALSE;
	}

	if (p_hdr->addr_data.common_data.src_endpoint !=
	    p_row->packet_info.dst_ep) {
		return ZB_FALSE;
	}

	if (p_hdr->addr_data.common_data.source.addr_type ==
	    ZB_ZCL_ADDR_TYPE_SHORT) {
		if (p_hdr->addr_data.common_data.source.u.short_addr !=
		    remote_node_short) {
			return ZB_FALSE;
		}
	} else {
		return ZB_FALSE;
	}

	if (p_hdr->cmd_id != ZB_ZCL_CMD_DEFAULT_RESP &&
	    p_hdr->cmd_id != ZB_ZCL_CMD_READ_ATTRIB_RESP &&
	    p_hdr->cmd_id != ZB_ZCL_CMD_WRITE_ATTRIB_RESP) {
		return ZB_FALSE;
	}

	return ZB_TRUE;
}

/**@brief Print the Read Attribute Response.
 *
 * @param bufid     Zigbee buffer ID with Read Attribute Response packet.
 * @param p_row     Pointer to a row in attr table.
 */
static void print_read_attr_response(zb_bufid_t bufid, attr_query_t * p_row)
{
	zb_zcl_read_attr_res_t * p_attr_resp;
	/* Get the contents of Read Attribute Response frame. */
	ZB_ZCL_GENERAL_GET_NEXT_READ_ATTR_RES(bufid, p_attr_resp);
	if (p_attr_resp->status == ZB_ZCL_STATUS_SUCCESS) {
		char attr_buf[40];
		int bytes_written = zcl_attr_to_str(attr_buf, sizeof(attr_buf),
						    p_attr_resp->attr_type,
						    p_attr_resp->attr_value);

		if (bytes_written < 0) {
			print_error(p_row->shell,
				    "Unable to print attribute value", ZB_TRUE);
		} else {
			shell_print(p_row->shell, "ID: %d Type: %x Value: %s",
				    p_attr_resp->attr_id,
				    p_attr_resp->attr_type, attr_buf);
			print_done(p_row->shell, ZB_FALSE);
		}
	} else {
		shell_print(p_row->shell, "Error: Status %d",
			    p_attr_resp->status);
	}
}

/**@brief Print the Write Attribute Response.
 *
 * @param bufid     Zigbee buffer ID with Write Attribute Response packet.
 * @param p_row     Pointer to a row in attr table.
 */
static void print_write_attr_response(zb_bufid_t bufid, attr_query_t * p_row)
{
	zb_zcl_write_attr_res_t * p_attr_resp;
	/* Get the contents of Write Attribute Response frame. */
	ZB_ZCL_GET_NEXT_WRITE_ATTR_RES(bufid, p_attr_resp);

	if (!p_attr_resp) {
		print_error(p_row->shell, "No attribute could be retrieved",
			    ZB_TRUE);
		return;
	}

	if (p_attr_resp->status != ZB_ZCL_STATUS_SUCCESS) {
		shell_print(p_row->shell, "Error: Status %d",
			    p_attr_resp->status);
		return;
	}

	print_done(p_row->shell, ZB_FALSE);
}

/**@brief The Handler to 'intercept' every frame coming to the endpoint.
 *
 * @param bufid    ZBOSS buffer id.
 */
static zb_uint8_t cli_agent_ep_handler_attr(zb_bufid_t bufid)
{
	zb_zcl_parsed_hdr_t * p_cmd_info;
	zb_int8_t row;

	p_cmd_info = ZB_BUF_GET_PARAM(bufid, zb_zcl_parsed_hdr_t);

	/* Get the row in the requests table according by the seq number. */
	row = get_attr_table_row_by_sn(p_cmd_info->seq_number);
	if (row == -1) {
		return ZB_FALSE;
	}

	attr_query_t * p_row = &(m_attr_table[row]);
	if (!is_response(p_cmd_info, p_row)) {
		return ZB_FALSE;
	}

	if (p_cmd_info->cmd_id == ZB_ZCL_CMD_DEFAULT_RESP) {
		zb_zcl_default_resp_payload_t * p_def_resp;
		p_def_resp = ZB_ZCL_READ_DEFAULT_RESP(bufid);
		shell_error(p_row->shell, "Error: Default Response received; ");
		shell_error(p_row->shell, "Command: %d, Status: %d ",
			    p_def_resp->command_id, p_def_resp->status);
	} else {
		if (p_row->req_type == ATTR_READ_REQUEST) {
			print_read_attr_response(bufid, p_row);
		} else {
			print_write_attr_response(bufid, p_row);
		}
	}
	/* Cancel the ongoing alarm which was to erase the row ... */
	(void)(ZB_SCHEDULE_APP_ALARM_CANCEL(invalidate_row_cb, row));
	/* ... and erase it manually. */
	invalidate_row(row);

	zb_buf_free(bufid);
	return ZB_TRUE;
}

/**@brief Actually construct the Read or Write Attribute frame and send it.
 *
 * @param param  Row of the read attribute table to refer to.
 */
static zb_void_t read_write_attr_send(zb_uint8_t param)
{
	zb_ret_t zb_err_code;
	zb_uint8_t row = param;
	attr_query_t *p_row = &(m_attr_table[row]);

	p_row->seq_num = ZCL_CTX().seq_number;

	zb_err_code = ZB_SCHEDULE_APP_ALARM(invalidate_row_cb, row,
					    ATTRIBUTE_ROW_TIMEOUT_S *
					     ZB_TIME_ONE_SECOND);
	if (zb_err_code != RET_OK) {
		print_error(p_row->shell, "No frame left - wait a bit",
			    ZB_FALSE);
		/* Invalidate row so that we can reuse it. */
		invalidate_row(row);
		zb_buf_free(p_row->packet_info.buffer);
		return;
	}

	/* Send the actual frame. */
	zb_err_code = zb_zcl_finish_and_send_packet_new(
				p_row->packet_info.buffer,
				p_row->packet_info.ptr,
				&(p_row->packet_info.dst_addr),
				p_row->packet_info.dst_addr_mode,
				p_row->packet_info.dst_ep,
				p_row->packet_info.ep,
				p_row->packet_info.prof_id,
				p_row->packet_info.cluster_id,
				p_row->packet_info.cb,
				0,
				p_row->packet_info.disable_aps_ack,
				0);

	if (zb_err_code != RET_OK) {
		print_error(p_row->shell, "Can not send ZCL frame",
			    ZB_FALSE);
		/* Invalidate row so that we can reuse it. */
		invalidate_row(row);
		zb_buf_free(p_row->packet_info.buffer);
		return;
	}
}

/**@brief Retrieve the attribute value of the remote node.
 *
 * @code
 * zcl attr read <h:dst_addr> <d:ep> <h:cluster> [-c] <h:profile> <h:attr_id>
 * @endcode
 *
 * Read the value of the attribute `attr_id` in the cluster `cluster`.
 * The cluster belongs to the profile `profile`, which resides on the endpoint
 * `ep` of the remote node `dst_addr`. If the attribute is on the client role
 * side of the cluster, use the `-c` switch.
 */
int cmd_zb_readattr(const struct shell *shell, size_t argc, char **argv)
{
	zb_ret_t zb_err_code;
	zb_uint8_t *p_cmd_buf;
	zb_int8_t row = get_free_row_attr_table();

	bool is_direction_present = ((argc == 7) && !strcmp(argv[4], "-c"));

	if (argc != 6 && !is_direction_present) {
		print_error(shell, "Wrong number of arguments", ZB_FALSE);
		return -EINVAL;
	}

	if (row == -1) {
		print_error(shell, "Request pool empty - wait a bit", ZB_FALSE);
		return -ENOEXEC;
	}

	attr_query_t *p_row = &(m_attr_table[row]);

	p_row->packet_info.dst_addr_mode = parse_address(
						*(++argv),
						&(p_row->packet_info.dst_addr),
						ADDR_ANY);
	if (p_row->packet_info.dst_addr_mode == ADDR_INVALID) {
		print_error(shell, "Invalid address", ZB_FALSE);
		return -EINVAL;
	}

	(void)(sscan_uint8(*(++argv), &(p_row->packet_info.dst_ep)));

	if (!parse_hex_u16(*(++argv), &(p_row->cluster_id))) {
		print_error(shell, "Invalid cluster id", ZB_FALSE);
		return -EINVAL;
	}

	if (is_direction_present) {
		p_row->direction = ZB_ZCL_FRAME_DIRECTION_TO_CLI;
		++argv;
	} else {
		p_row->direction = ZB_ZCL_FRAME_DIRECTION_TO_SRV;
	}

	if (!parse_hex_u16(*(++argv), &(p_row->profile_id))) {
		print_error(shell, "Invalid profile id", ZB_FALSE);
		return -EINVAL;
	}

	if (!parse_hex_u16(*(++argv), &(p_row->attr_id))) {
		print_error(shell, "Invalid attribute id", ZB_FALSE);
		return -EINVAL;
	}

	p_row->req_type = ATTR_READ_REQUEST;
	atomic_set(&p_row->taken, ZB_TRUE);

	/* Put the shell instance to be used later. */
	p_row->shell = (const struct shell*)shell;

	zb_bufid_t bufid = zb_buf_get_out();

	ZB_ZCL_GENERAL_INIT_READ_ATTR_REQ_A(bufid, p_cmd_buf, p_row->direction,
					    ZB_ZCL_ENABLE_DEFAULT_RESPONSE);
	ZB_ZCL_GENERAL_ADD_ID_READ_ATTR_REQ(p_cmd_buf, p_row->attr_id);

	/* Fill the structure for sending ZCL frame. */
	p_row->packet_info.buffer = bufid;
	p_row->packet_info.ptr = p_cmd_buf;
	/* DstAddr already set. */
	/* DstAddr Mode already set. */
	/* Remote endpoint already set. */
	p_row->packet_info.ep = zb_get_cli_endpoint();
	p_row->packet_info.prof_id = p_row->profile_id;
	p_row->packet_info.cluster_id = p_row->cluster_id;
	p_row->packet_info.cb = frame_acked_cb;
	p_row->packet_info.disable_aps_ack = ZB_FALSE;

	zb_err_code = zigbee_schedule_callback(read_write_attr_send, row);

	if (zb_err_code != RET_OK) {
		print_error(shell, "No frame left - wait a bit", ZB_FALSE);
		/* Invalidate row so that we can reuse it. */
		invalidate_row(row);
		zb_buf_free(bufid);
		return -ENOEXEC;
	}
	return 0;
}

/**@brief Write the attribute value to the remote node.
 *
 * @code
 * zcl attr write <h:dst_addr> <d:ep> <h:cluster> <h:profile> <h:attr_id>
 *                <h:attr_type> <h:attr_value>
 * @endcode
 *
 * Write the `attr_value` value of the attribute `attr_id` of the type
 * `attr_type` in the cluster `cluster`. The cluster belongs to the profile
 * `profile`, which resides on the endpoint `ep` of the remote node `dst_addr`.
 *
 * @note The `attr_value` value must be in hexadecimal format, unless it is a
 * string (`attr_type == 42`), then it must be a string.
 *
 */
int cmd_zb_writeattr(const struct shell *shell, size_t argc, char **argv)
{
	zb_ret_t zb_err_code;
	zb_uint8_t *p_cmd_buf;
	zb_int8_t row = get_free_row_attr_table();

	bool is_direction_present = ((argc == 9) && !strcmp(argv[4], "-c"));

	if (argc != 8 && !is_direction_present) {
		print_error(shell, "Wrong number of arguments", ZB_FALSE);
		return -EINVAL;
	}

	if (row == -1) {
		print_error(shell, "Request pool empty - wait a bit", ZB_FALSE);
		return -ENOEXEC;
	}

	attr_query_t * p_row = &(m_attr_table[row]);

	p_row->packet_info.dst_addr_mode = parse_address(
						*(++argv),
						&(p_row->packet_info.dst_addr),
						ADDR_ANY);
	if (p_row->packet_info.dst_addr_mode ==  ADDR_INVALID) {
		print_error(shell, "Invalid address", ZB_FALSE);
		return -EINVAL;
	}

	(void)(sscan_uint8(*(++argv), &(p_row->packet_info.dst_ep)));

	if (!parse_hex_u16(*(++argv), &(p_row->cluster_id))) {
		print_error(shell, "Invalid cluster id", ZB_FALSE);
		return -EINVAL;
	}

	if (is_direction_present) {
		p_row->direction = ZB_ZCL_FRAME_DIRECTION_TO_CLI;
		++argv;
	} else {
		p_row->direction = ZB_ZCL_FRAME_DIRECTION_TO_SRV;
	}

	if (!parse_hex_u16(*(++argv), &(p_row->profile_id))) {
		print_error(shell, "Invalid profile id", ZB_FALSE);
		return -EINVAL;
	}

	if (!parse_hex_u16(*(++argv), &(p_row->attr_id))) {
		print_error(shell, "Invalid attribute id", ZB_FALSE);
		return -EINVAL;
	}

	if (!parse_hex_u8(*(++argv), &(p_row->attr_type))) {
		print_error(shell, "Invalid attribute type", ZB_FALSE);
		return -EINVAL;
	}

	u8_t len = strlen(*(++argv));
	if (p_row->attr_type == ZB_ZCL_ATTR_TYPE_CHAR_STRING) {
		p_row->attr_value[0] = len;
		strncpy((zb_char_t*)(p_row->attr_value + 1), *argv,
			sizeof(p_row->attr_value) - 1);
	} else if (!parse_hex_str(*argv, len, p_row->attr_value,
				  sizeof(p_row->attr_value), true)) {
		print_error(shell, "Invalid attribute value", ZB_FALSE);
		return -EINVAL;
	}

	p_row->req_type = ATTR_WRITE_REQUEST;
	atomic_set(&p_row->taken, ZB_TRUE);
	/* Put the shell instance to be used later. */
	p_row->shell = (const struct shell*)shell;

	zb_bufid_t bufid = zb_buf_get_out();

	ZB_ZCL_GENERAL_INIT_WRITE_ATTR_REQ_A(bufid, p_cmd_buf, p_row->direction,
					     ZB_ZCL_ENABLE_DEFAULT_RESPONSE);
	ZB_ZCL_GENERAL_ADD_VALUE_WRITE_ATTR_REQ(p_cmd_buf, p_row->attr_id,
						p_row->attr_type,
						p_row->attr_value);

	/* Fill the structure for sending ZCL frame.  */
	p_row->packet_info.buffer = bufid;
	p_row->packet_info.ptr = p_cmd_buf;
	/* DstAddr already set. */
	/* DstAddr Mode already set. */
	/* Destination endpoint already set. */
	p_row->packet_info.ep = zb_get_cli_endpoint();
	p_row->packet_info.prof_id = p_row->profile_id;
	p_row->packet_info.cluster_id = p_row->cluster_id;
	p_row->packet_info.cb = frame_acked_cb;
	p_row->packet_info.disable_aps_ack = ZB_FALSE;

	zb_err_code = zigbee_schedule_callback(read_write_attr_send, row);

	if (zb_err_code != RET_OK) {
		print_error(shell, "No frame left - wait a bit", ZB_FALSE);
		/* Invalidate row so that we can reuse it. */
		invalidate_row(row);
		zb_buf_free(bufid);
		return -ENOEXEC;
	}
	return 0;
}

/**@brief Endpoint handlers
 */
#ifndef DEVELOPMENT_TODO
#error "Endpoint handler to be done here."
NRF_ZIGBEE_EP_HANDLER_REGISTER(attr, cli_agent_ep_handler_attr);
#endif
