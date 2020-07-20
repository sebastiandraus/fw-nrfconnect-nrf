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

enum attr_req_type {
	ATTR_READ_REQUEST,
	ATTR_WRITE_REQUEST
};

/**@brief The row of the table which holds the requests which were sent.
 *
 * @details We compare the incoming responses with the rows contents
 *          to determine if it is the answer. The structure corresponds to both
 *          read and write requests.
 *          The key parameter is the sequence number.
 */
struct attr_query {
	bool taken;
	zb_uint8_t seq_num;
	zb_uint8_t attr_type;
	zb_uint8_t attr_value[32];
	zb_uint16_t profile_id;
	zb_uint16_t cluster_id;
	zb_uint16_t attr_id;
	const struct shell *shell;
	enum attr_req_type req_type;
	zb_zcl_frame_direction_t direction;
	struct zcl_packet_info packet_info;
};

static struct attr_query attr_table[ATTRIBUTE_TABLE_SIZE];

/**@brief Get the first free row in the attributes table, return -1 if none.
 */
static zb_int8_t get_free_row_attr_table(void)
{
	int i;

	for (i = 0; i < ATTRIBUTE_TABLE_SIZE; i++) {
		if (attr_table[i].taken == false) {
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
		if (attr_table[i].taken == true) {
			if (attr_table[i].seq_num == sernum) {
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
static void invalidate_row(zb_uint8_t row)
{
	if (row < ATTRIBUTE_TABLE_SIZE) {
		attr_table[row].taken = false;
		ZB_MEMSET(&(attr_table[row]), 0x00, sizeof(struct attr_query));
	}
}
/**@brief Invalidate row after the timeout - ZBOSS callback.
 *
 * @param row     Number of row to invalidate.
 */
static void invalidate_row_cb(zb_uint8_t row)
{
	zb_cli_print_error(attr_table[row].shell, "Request timed out",
			   ZB_FALSE);
	invalidate_row(row);
}

static void frame_acked_cb(zb_bufid_t bufid)
{
	if (bufid) {
		zb_buf_free(bufid);
	}
}

/**@brief Check if the frame we received is the response to our request
 *        in the table.
 *
 * @param zcl_hdr             Pointer to the parsed header of the frame.
 * @param attr_query_entry    Pointer to the row in the table to check against.
 *
 * @return Whether it is response or not.
 */
static zb_bool_t is_response(zb_zcl_parsed_hdr_t *zcl_hdr,
			     struct attr_query *attr_query_entry)
{
	zb_uint16_t remote_node_short = 0;
	struct zcl_packet_info *packet_info = &attr_query_entry->packet_info;

	if (attr_query_entry->packet_info.dst_addr_mode ==
	    ZB_APS_ADDR_MODE_64_ENDP_PRESENT) {
		remote_node_short = zb_address_short_by_ieee(
					packet_info->dst_addr.addr_long);
	} else {
		remote_node_short = packet_info->dst_addr.addr_short;
	}

	if (zcl_hdr->cluster_id != attr_query_entry->cluster_id) {
		return ZB_FALSE;
	}

	if (zcl_hdr->profile_id != attr_query_entry->profile_id) {
		return ZB_FALSE;
	}

	if (zcl_hdr->addr_data.common_data.src_endpoint !=
	    packet_info->dst_ep) {
		return ZB_FALSE;
	}

	if (zcl_hdr->addr_data.common_data.source.addr_type ==
	    ZB_ZCL_ADDR_TYPE_SHORT) {
		if (zcl_hdr->addr_data.common_data.source.u.short_addr !=
		    remote_node_short) {
			return ZB_FALSE;
		}
	} else {
		return ZB_FALSE;
	}

	if (zcl_hdr->cmd_id != ZB_ZCL_CMD_DEFAULT_RESP &&
	    zcl_hdr->cmd_id != ZB_ZCL_CMD_READ_ATTRIB_RESP &&
	    zcl_hdr->cmd_id != ZB_ZCL_CMD_WRITE_ATTRIB_RESP) {
		return ZB_FALSE;
	}

	return ZB_TRUE;
}

/**@brief Print the Read Attribute Response.
 *
 * @param bufid             Zigbee buffer ID with Read Attribute Response
 *                          packet.
 * @param attr_query_entry  Pointer to a row in attr table.
 */
static void print_read_attr_response(zb_bufid_t bufid,
				     struct attr_query *attr_query_entry)
{
	zb_zcl_read_attr_res_t *attr_resp;

	/* Get the contents of Read Attribute Response frame. */
	ZB_ZCL_GENERAL_GET_NEXT_READ_ATTR_RES(bufid, attr_resp);
	if (attr_resp->status == ZB_ZCL_STATUS_SUCCESS) {
		char attr_buf[40];
		int bytes_written = zb_cli_zcl_attr_to_str(
					attr_buf, sizeof(attr_buf),
					attr_resp->attr_type,
					attr_resp->attr_value);

		if (bytes_written < 0) {
			zb_cli_print_error(attr_query_entry->shell,
					   "Unable to print attribute value",
					   ZB_TRUE);
		} else {
			shell_print(attr_query_entry->shell,
				    "ID: %d Type: %x Value: %s",
				    attr_resp->attr_id, attr_resp->attr_type,
				    attr_buf);
			zb_cli_print_done(attr_query_entry->shell, ZB_FALSE);
		}
	} else {
		shell_print(attr_query_entry->shell, "Error: Status %d",
			    attr_resp->status);
	}
}

/**@brief Print the Write Attribute Response.
 *
 * @param bufid             Zigbee buffer ID with Write Attribute Response
 *                          packet.
 * @param attr_query_entry  Pointer to a row in attr table.
 */
static void print_write_attr_response(zb_bufid_t bufid,
				      struct attr_query *attr_query_entry)
{
	zb_zcl_write_attr_res_t *attr_resp;

	/* Get the contents of Write Attribute Response frame. */
	ZB_ZCL_GET_NEXT_WRITE_ATTR_RES(bufid, attr_resp);

	if (!attr_resp) {
		zb_cli_print_error(attr_query_entry->shell,
				   "No attribute could be retrieved", ZB_TRUE);
		return;
	}

	if (attr_resp->status != ZB_ZCL_STATUS_SUCCESS) {
		shell_print(attr_query_entry->shell, "Error: Status %d",
			    attr_resp->status);
		return;
	}

	zb_cli_print_done(attr_query_entry->shell, ZB_FALSE);
}

/**@brief The Handler to 'intercept' every frame coming to the endpoint.
 *
 * @param bufid    ZBOSS buffer id.
 */
zb_uint8_t cli_agent_ep_handler_attr(zb_bufid_t bufid)
{
	zb_zcl_parsed_hdr_t *zcl_hdr;
	struct attr_query *attr_query_entry;
	zb_int8_t row;

	zcl_hdr = ZB_BUF_GET_PARAM(bufid, zb_zcl_parsed_hdr_t);

	/* Get the row in the requests table according by the seq number. */
	row = get_attr_table_row_by_sn(zcl_hdr->seq_number);
	if (row == -1) {
		return ZB_FALSE;
	}

	attr_query_entry = &(attr_table[row]);
	if (!is_response(zcl_hdr, attr_query_entry)) {
		return ZB_FALSE;
	}

	if (zcl_hdr->cmd_id == ZB_ZCL_CMD_DEFAULT_RESP) {
		zb_zcl_default_resp_payload_t *def_resp;

		def_resp = ZB_ZCL_READ_DEFAULT_RESP(bufid);
		shell_error(attr_query_entry->shell,
			    "Error: Default Response received; ");
		shell_error(attr_query_entry->shell, "Command: %d, Status: %d ",
			    def_resp->command_id, def_resp->status);
	} else {
		if (attr_query_entry->req_type == ATTR_READ_REQUEST) {
			print_read_attr_response(bufid, attr_query_entry);
		} else {
			print_write_attr_response(bufid, attr_query_entry);
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
 * @param row  Row of the read attribute table to refer to.
 */
static void read_write_attr_send(zb_uint8_t row)
{
	zb_ret_t zb_err_code;
	struct attr_query *attr_query_entry = &(attr_table[row]);

	zb_err_code = ZB_SCHEDULE_APP_ALARM(invalidate_row_cb, row,
					    ATTRIBUTE_ROW_TIMEOUT_S *
					     ZB_TIME_ONE_SECOND);
	if (zb_err_code != RET_OK) {
		zb_cli_print_error(attr_query_entry->shell,
				   "No frame left - wait a bit",
				   ZB_FALSE);
		/* Invalidate row so that we can reuse it. */
		invalidate_row(row);
		zb_buf_free(attr_query_entry->packet_info.buffer);
		return;
	}

	/* Send the actual frame. */
	zb_err_code = zb_zcl_finish_and_send_packet_new(
				attr_query_entry->packet_info.buffer,
				attr_query_entry->packet_info.ptr,
				&(attr_query_entry->packet_info.dst_addr),
				attr_query_entry->packet_info.dst_addr_mode,
				attr_query_entry->packet_info.dst_ep,
				attr_query_entry->packet_info.ep,
				attr_query_entry->packet_info.prof_id,
				attr_query_entry->packet_info.cluster_id,
				attr_query_entry->packet_info.cb,
				0,
				attr_query_entry->packet_info.disable_aps_ack,
				0);

	if (zb_err_code != RET_OK) {
		zb_cli_print_error(attr_query_entry->shell,
				   "Can not send ZCL frame",
				   ZB_FALSE);
		/* Invalidate row so that we can reuse it. */
		invalidate_row(row);
		zb_buf_free(attr_query_entry->packet_info.buffer);
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
	zb_bufid_t bufid;
	zb_uint8_t *cmd_buf_ptr;
	zb_int8_t row = get_free_row_attr_table();

	bool is_direction_present = ((argc == 7) && !strcmp(argv[4], "-c"));

	if (argc != 6 && !is_direction_present) {
		zb_cli_print_error(shell, "Wrong number of arguments",
				   ZB_FALSE);
		return -EINVAL;
	}

	if (row == -1) {
		zb_cli_print_error(shell, "Request pool empty - wait a bit",
				   ZB_FALSE);
		return -ENOEXEC;
	}

	struct attr_query *attr_query_entry = &(attr_table[row]);

	attr_query_entry->packet_info.dst_addr_mode =
		parse_address(*(++argv),
			      &(attr_query_entry->packet_info.dst_addr),
			      ADDR_ANY);

	if (attr_query_entry->packet_info.dst_addr_mode == ADDR_INVALID) {
		zb_cli_print_error(shell, "Invalid address", ZB_FALSE);
		return -EINVAL;
	}

	(void)(zb_cli_sscan_uint8(*(++argv),
				  &(attr_query_entry->packet_info.dst_ep)));

	if (!parse_hex_u16(*(++argv), &(attr_query_entry->cluster_id))) {
		zb_cli_print_error(shell, "Invalid cluster id", ZB_FALSE);
		return -EINVAL;
	}

	if (is_direction_present) {
		attr_query_entry->direction = ZB_ZCL_FRAME_DIRECTION_TO_CLI;
		++argv;
	} else {
		attr_query_entry->direction = ZB_ZCL_FRAME_DIRECTION_TO_SRV;
	}

	if (!parse_hex_u16(*(++argv), &(attr_query_entry->profile_id))) {
		zb_cli_print_error(shell, "Invalid profile id", ZB_FALSE);
		return -EINVAL;
	}

	if (!parse_hex_u16(*(++argv), &(attr_query_entry->attr_id))) {
		zb_cli_print_error(shell, "Invalid attribute id", ZB_FALSE);
		return -EINVAL;
	}

	attr_query_entry->req_type = ATTR_READ_REQUEST;
	attr_query_entry->taken = true;

	/* Put the shell instance to be used later. */
	attr_query_entry->shell = shell;

	/* Make sure ZBOSS buffer API is called safely. */
	zb_osif_disable_all_inter();
	bufid = zb_buf_get_out();
	zb_osif_enable_all_inter();

	if (!bufid) {
		zb_cli_print_error(shell,
				   "Failed to execute command (buf alloc failed)",
				   ZB_FALSE);
		invalidate_row(row);
		return -ENOEXEC;
	}

	/* Get the ZCL packet sequence number. */
	attr_query_entry->seq_num = ZCL_CTX().seq_number;

	ZB_ZCL_GENERAL_INIT_READ_ATTR_REQ_A(bufid, cmd_buf_ptr,
					    attr_query_entry->direction,
					    ZB_ZCL_ENABLE_DEFAULT_RESPONSE);
	ZB_ZCL_GENERAL_ADD_ID_READ_ATTR_REQ(cmd_buf_ptr,
					    attr_query_entry->attr_id);

	/* Fill the structure for sending ZCL frame. */
	attr_query_entry->packet_info.buffer = bufid;
	attr_query_entry->packet_info.ptr = cmd_buf_ptr;
	/* DstAddr, DstAddr Mode, Destination endpoint are already set. */
	attr_query_entry->packet_info.ep = zb_cli_get_endpoint();
	attr_query_entry->packet_info.prof_id = attr_query_entry->profile_id;
	attr_query_entry->packet_info.cluster_id = attr_query_entry->cluster_id;
	attr_query_entry->packet_info.cb = frame_acked_cb;
	attr_query_entry->packet_info.disable_aps_ack = ZB_FALSE;

	zb_err_code = ZB_SCHEDULE_APP_CALLBACK(read_write_attr_send, row);

	if (zb_err_code != RET_OK) {
		zb_cli_print_error(shell, "No frame left - wait a bit",
				   ZB_FALSE);
		/* Invalidate row so that we can reuse it. */
		invalidate_row(row);

		/* Make sure ZBOSS buffer API is called safely. */
		zb_osif_disable_all_inter();
		zb_buf_free(bufid);
		zb_osif_enable_all_inter();

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
	zb_bufid_t bufid;
	zb_ret_t zb_err_code;
	zb_uint8_t *cmd_buf_ptr;
	zb_int8_t row = get_free_row_attr_table();

	bool is_direction_present = ((argc == 9) && !strcmp(argv[4], "-c"));

	if (argc != 8 && !is_direction_present) {
		zb_cli_print_error(shell, "Wrong number of arguments",
				   ZB_FALSE);
		return -EINVAL;
	}

	if (row == -1) {
		zb_cli_print_error(shell, "Request pool empty - wait a bit",
				   ZB_FALSE);
		return -ENOEXEC;
	}

	struct attr_query *attr_query_entry = &(attr_table[row]);

	attr_query_entry->packet_info.dst_addr_mode =
		parse_address(*(++argv),
			      &(attr_query_entry->packet_info.dst_addr),
			      ADDR_ANY);

	if (attr_query_entry->packet_info.dst_addr_mode == ADDR_INVALID) {
		zb_cli_print_error(shell, "Invalid address", ZB_FALSE);
		return -EINVAL;
	}

	(void)(zb_cli_sscan_uint8(*(++argv),
				  &(attr_query_entry->packet_info.dst_ep)));

	if (!parse_hex_u16(*(++argv), &(attr_query_entry->cluster_id))) {
		zb_cli_print_error(shell, "Invalid cluster id", ZB_FALSE);
		return -EINVAL;
	}

	if (is_direction_present) {
		attr_query_entry->direction = ZB_ZCL_FRAME_DIRECTION_TO_CLI;
		++argv;
	} else {
		attr_query_entry->direction = ZB_ZCL_FRAME_DIRECTION_TO_SRV;
	}

	if (!parse_hex_u16(*(++argv), &(attr_query_entry->profile_id))) {
		zb_cli_print_error(shell, "Invalid profile id", ZB_FALSE);
		return -EINVAL;
	}

	if (!parse_hex_u16(*(++argv), &(attr_query_entry->attr_id))) {
		zb_cli_print_error(shell, "Invalid attribute id", ZB_FALSE);
		return -EINVAL;
	}

	if (!parse_hex_u8(*(++argv), &(attr_query_entry->attr_type))) {
		zb_cli_print_error(shell, "Invalid attribute type", ZB_FALSE);
		return -EINVAL;
	}

	uint8_t len = strlen(*(++argv));

	if (attr_query_entry->attr_type == ZB_ZCL_ATTR_TYPE_CHAR_STRING) {
		attr_query_entry->attr_value[0] = len;
		strncpy((zb_char_t *)(attr_query_entry->attr_value + 1), *argv,
			sizeof(attr_query_entry->attr_value) - 1);
	} else if (!parse_hex_str(*argv, len, attr_query_entry->attr_value,
				  sizeof(attr_query_entry->attr_value), true)) {

		zb_cli_print_error(shell, "Invalid attribute value", ZB_FALSE);
		return -EINVAL;
	}

	attr_query_entry->req_type = ATTR_WRITE_REQUEST;
	attr_query_entry->taken = true;
	/* Put the shell instance to be used later. */
	attr_query_entry->shell = shell;

	/* Make sure ZBOSS buffer API is called safely. */
	zb_osif_disable_all_inter();
	bufid = zb_buf_get_out();
	zb_osif_enable_all_inter();

	if (!bufid) {
		zb_cli_print_error(shell,
				   "Failed to execute command (buf alloc failed)",
				   ZB_FALSE);
		invalidate_row(row);
		return -ENOEXEC;
	}

	/* Get the ZCL packet sequence number. */
	attr_query_entry->seq_num = ZCL_CTX().seq_number;

	ZB_ZCL_GENERAL_INIT_WRITE_ATTR_REQ_A(bufid, cmd_buf_ptr,
					     attr_query_entry->direction,
					     ZB_ZCL_ENABLE_DEFAULT_RESPONSE);
	ZB_ZCL_GENERAL_ADD_VALUE_WRITE_ATTR_REQ(cmd_buf_ptr,
						attr_query_entry->attr_id,
						attr_query_entry->attr_type,
						attr_query_entry->attr_value);

	/* Fill the structure for sending ZCL frame.  */
	attr_query_entry->packet_info.buffer = bufid;
	attr_query_entry->packet_info.ptr = cmd_buf_ptr;
	/* DstAddr, DstAddr Mode, Destination endpoint are already set. */
	attr_query_entry->packet_info.ep = zb_cli_get_endpoint();
	attr_query_entry->packet_info.prof_id = attr_query_entry->profile_id;
	attr_query_entry->packet_info.cluster_id = attr_query_entry->cluster_id;
	attr_query_entry->packet_info.cb = frame_acked_cb;
	attr_query_entry->packet_info.disable_aps_ack = ZB_FALSE;

	zb_err_code = ZB_SCHEDULE_APP_CALLBACK(read_write_attr_send, row);

	if (zb_err_code != RET_OK) {
		zb_cli_print_error(shell, "No frame left - wait a bit",
				   ZB_FALSE);
		/* Invalidate row so that we can reuse it. */
		invalidate_row(row);

		/* Make sure ZBOSS buffer API is called safely. */
		zb_osif_disable_all_inter();
		zb_buf_free(bufid);
		zb_osif_enable_all_inter();

		return -ENOEXEC;
	}
	return 0;
}
