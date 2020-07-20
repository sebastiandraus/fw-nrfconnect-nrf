/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <errno.h>
#include <shell/shell.h>

#include <zboss_api.h>
#include <zb_error_handler.h>
#include <zb_nrf_platform.h>
#include "zigbee_cli.h"
#include "zigbee_cli_utils.h"
#include "zigbee_cli_cmd_zcl.h"

/* Defines how many report attribute requests can be run concurrently. */
#define ZIGBEE_CLI_CONFIGURE_REPORT_TSN                  3
/* Defines how long to wait, in seconds, for Configure Reporting Response. */
#define ZIGBEE_CLI_CONFIGURE_REPORT_RESP_TIMEOUT         5
/* Defines default value for minimum interval inside configure
 * reporting request.
 */
#define ZIGBEE_CLI_CONFIGURE_REPORT_DEFAULT_MIN_INTERVAL 1
/* Defines default value for maximum interval inside configure
 * reporting request.
 */
#define ZIGBEE_CLI_CONFIGURE_REPORT_DEFAULT_MAX_INTERVAL 60
/* Defines default value for minimum value change inside configure
 * reporting request.
 */
#define ZIGBEE_CLI_CONFIGURE_REPORT_DEFAULT_VALUE_CHANGE NULL
/* Defines default value for minimum interval configured
 * in order to turn off reporting. See ZCL specification, sec. 2.5.7.1.5.
 * This can be any value, only max_interval parameters is relevant.
 */
#define ZIGBEE_CLI_CONFIGURE_REPORT_OFF_MIN_INTERVAL 0x000F
/* Defines default value for maximum interval inside configure
 * reporting request. See ZCL specification, sec. 2.5.7.1.6.
 */
#define ZIGBEE_CLI_CONFIGURE_REPORT_OFF_MAX_INTERVAL 0xFFFF

LOG_MODULE_REGISTER(report, CONFIG_ZIGBEE_SHELL_LOG_LEVEL);

/* This structure representing fields required to construct configure
 * reporting requests.
 */
struct configure_reporting_req {
	zb_uint8_t attr_type;
	zb_uint16_t attr_id;
	zb_uint16_t interval_min;
	zb_uint16_t interval_max;
};

/* This structure allows for binding ZBOSS transaction and CLI object. */
struct tsn_ctx {
	bool taken;
	bool is_broadcast;
	uint8_t tsn;
	const struct shell *shell;
	struct zcl_packet_info packet_info;
	struct configure_reporting_req req;
};

static struct tsn_ctx tsn_ctx[ZIGBEE_CLI_CONFIGURE_REPORT_TSN];


/**@brief Return a pointer to context with the given transaction
 *        sequence number.
 *
 * @param[in] tsn ZBOSS transaction sequence number
 *
 * @return a pointer to context or NULL if context for given TSN wasn't found.
 */
static struct tsn_ctx *get_ctx_by_tsn(uint8_t tsn)
{
	for (uint8_t i = 0; i < ARRAY_SIZE(tsn_ctx); i++) {
		if ((tsn_ctx[i].taken == true) &&
		    (tsn_ctx[i].tsn == tsn)) {
			return &tsn_ctx[i];
		}
	}

	return NULL;
}

/**@brief Get a pointer to a free context.
 *
 * @return a pointer to context structure or NULL if all contexts are taken.
 */
static struct tsn_ctx *get_free_tsn_ctx(void)
{
	for (uint8_t i = 0; i < ARRAY_SIZE(tsn_ctx); i++) {
		if (!tsn_ctx[i].taken) {
			return &tsn_ctx[i];
		}
	}

	return NULL;
}

/**
 * Invalidate context.
 *
 * @param[in] tsn_ctx_entry a pointer to transaction context.
 */
static void invalidate_ctx(struct tsn_ctx *tsn_ctx_entry)
{
	tsn_ctx_entry->taken = false;
	tsn_ctx_entry->tsn = 0xFF;
	tsn_ctx_entry->shell = NULL;
	memset(&(tsn_ctx_entry->packet_info), 0x00,
	       sizeof(struct zcl_packet_info));
}

/**@brief Handles timeout error and invalidates configure reporting transaction.
 *
 * @param[in] tsn ZBOSS transaction sequence number
 */
static void cmd_zb_subscribe_unsubscribe_timeout(uint8_t tsn)
{
	struct tsn_ctx *tsn_ctx_entry = get_ctx_by_tsn(tsn);

	if (!tsn_ctx_entry) {
		return;
	}

	zb_cli_print_error(tsn_ctx_entry->shell, "Request timed out", ZB_FALSE);
	invalidate_ctx(tsn_ctx_entry);
}

/**@brief Print the Configure Reporting Response
 *
 * @param tsn_ctx_entry[in]  Pointer to context structure
 * @param bufid[in]          ZBOSS buffer id
 */
static void cmd_zb_subscribe_unsubscribe_cb(struct tsn_ctx *tsn_ctx_entry,
					    zb_bufid_t bufid)
{
	zb_ret_t zb_err_code;
	zb_bool_t failed = ZB_FALSE;
	zb_zcl_configure_reporting_res_t *resp = NULL;

	zb_err_code = ZB_SCHEDULE_APP_ALARM_CANCEL(
			cmd_zb_subscribe_unsubscribe_timeout,
			ZB_ALARM_ANY_PARAM);
	if (zb_err_code != RET_OK) {
		zb_cli_print_error(tsn_ctx_entry->shell,
				   "Unable to cancel timeout timer", ZB_TRUE);
		goto free_tsn_ctx;
	}

	/* Check if response contains only status code. */
	if (sizeof(zb_zcl_configure_reporting_res_t) > zb_buf_len(bufid)) {
		resp = (zb_zcl_configure_reporting_res_t *)zb_buf_begin(bufid);

		if (resp->status == ZB_ZCL_STATUS_SUCCESS) {
			zb_cli_print_done(tsn_ctx_entry->shell, ZB_FALSE);
		} else {
			shell_error(tsn_ctx_entry->shell, "Error: Unable to configure reporting. Status: %d",
				    resp->status);
		}
		goto free_tsn_ctx;
	}

	/* Received a full Configure Reporting Response frame. */
	ZB_ZCL_GENERAL_GET_NEXT_CONFIGURE_REPORTING_RES(bufid, resp);
	if (resp == NULL) {
		zb_cli_print_error(tsn_ctx_entry->shell, "Unable to parse configure reporting response",
				   ZB_TRUE);
		goto free_tsn_ctx;
	}

	while (resp != NULL) {
		if (resp->status == ZB_ZCL_STATUS_SUCCESS) {
			switch (resp->direction) {
			case ZB_ZCL_CONFIGURE_REPORTING_SEND_REPORT:
				shell_print(tsn_ctx_entry->shell,
					    "Local subscription to attribute ID %hx updated",
					    resp->attr_id);
				break;

			case ZB_ZCL_CONFIGURE_REPORTING_RECV_REPORT:
				shell_print(tsn_ctx_entry->shell,
					    "Remote node subscription to receive attribute ID %hx updated",
					    resp->attr_id);
				break;

			default:
				shell_error(tsn_ctx_entry->shell,
					    "Error: Unknown reporting configuration direction for attribute %hx",
					    resp->attr_id);
				failed = ZB_TRUE;
				break;
			}
		} else {
			shell_error(tsn_ctx_entry->shell, "Error: Unable to configure attribute %hx reporting. Status: %hd",
				    resp->attr_id, resp->status);
			failed = ZB_TRUE;
		}
		ZB_ZCL_GENERAL_GET_NEXT_CONFIGURE_REPORTING_RES(bufid, resp);
	}

	if (failed == ZB_TRUE) {
		zb_cli_print_error(tsn_ctx_entry->shell, "One or more attributes reporting were not configured successfully",
				   ZB_TRUE);
	} else {
		zb_cli_print_done(tsn_ctx_entry->shell, ZB_FALSE);
	}

free_tsn_ctx:
	invalidate_ctx(tsn_ctx_entry);
	zb_buf_free(bufid);
}

/**@brief Print the Report Attribute Command
 *
 * @param zcl_hdr[in]    Pointer to parsed ZCL header
 * @param bufid[in]      ZBOSS buffer id
 */
static void print_attr_update(zb_zcl_parsed_hdr_t *zcl_hdr, zb_bufid_t bufid)
{
	zb_zcl_report_attr_req_t *attr_resp = NULL;
	zb_zcl_addr_t remote_node_data = zcl_hdr->addr_data.common_data.source;
	int bytes_written = 0;
	char print_buf[255];

	if (remote_node_data.addr_type == ZB_ZCL_ADDR_TYPE_SHORT) {
		LOG_INF("Received value updates from the remote node 0x%04x",
			remote_node_data.u.short_addr);
	} else {
		bytes_written = ieee_addr_to_str(print_buf, sizeof(print_buf),
						 remote_node_data.u.ieee_addr);
		if (bytes_written < 0) {
			LOG_INF("Received value updates from the remote node (unknown address)");
		} else {
			LOG_INF("Received value updates from the remote node 0x%s",
				print_buf);
		}
	}

	/* Get the contents of Read Attribute Response frame. */
	ZB_ZCL_GENERAL_GET_NEXT_REPORT_ATTR_REQ(bufid, attr_resp);
	while (attr_resp != NULL) {
		bytes_written = 0;
		bytes_written = zb_cli_zcl_attr_to_str(
					&print_buf[bytes_written],
					(sizeof(print_buf) - bytes_written),
					attr_resp->attr_type,
					attr_resp->attr_value);

		if (bytes_written < 0) {
			LOG_ERR("    Unable to print updated attribute value");
		} else {
			LOG_INF("    Profile: 0x%04x Cluster: 0x%04x Attribute: 0x%04x Type: %hu Value: %s",
				zcl_hdr->profile_id, zcl_hdr->cluster_id,
				attr_resp->attr_id, attr_resp->attr_type,
				print_buf);
		}

		ZB_ZCL_GENERAL_GET_NEXT_REPORT_ATTR_REQ(bufid, attr_resp);
	}
}

/**@brief The Handler to 'intercept' every frame coming to the endpoint
 *
 * @param bufid[in]  ZBOSS buffer id.
 *
 * @returns ZB_TRUE if ZCL command was processed.
 */
zb_uint8_t cli_agent_ep_handler_report(zb_bufid_t bufid)
{
	struct tsn_ctx *tsn_ctx_entry;
	zb_zcl_parsed_hdr_t *cmd_info = ZB_BUF_GET_PARAM(bufid,
							 zb_zcl_parsed_hdr_t);

	if (cmd_info->cmd_id == ZB_ZCL_CMD_REPORT_ATTRIB) {
		print_attr_update(cmd_info, bufid);
		zb_buf_free(bufid);
		return ZB_TRUE;

	} else if (cmd_info->cmd_id == ZB_ZCL_CMD_CONFIG_REPORT_RESP) {
		/* Find command context by ZCL sequence number. */
		tsn_ctx_entry = get_ctx_by_tsn(cmd_info->seq_number);
		if (tsn_ctx_entry != NULL) {
			cmd_zb_subscribe_unsubscribe_cb(tsn_ctx_entry, bufid);
			return ZB_TRUE;
		}
	}

	return ZB_FALSE;
}

/**@brief Function to send Configure Reporting command.
 *
 * @param[in] param  Number of row of `tsn_ctx` table from which information
 *                   about the ZCL packet are taken.
 */
static zb_void_t send_reporting_frame(zb_uint8_t param)
{
	zb_ret_t zb_err_code;
	struct tsn_ctx *row = &(tsn_ctx[param]);

	/* Send the actual frame. */
	zb_err_code = zb_zcl_finish_and_send_packet_new(
				row->packet_info.buffer,
				row->packet_info.ptr,
				&(row->packet_info.dst_addr),
				row->packet_info.dst_addr_mode,
				row->packet_info.dst_ep,
				row->packet_info.ep,
				row->packet_info.prof_id,
				row->packet_info.cluster_id,
				row->packet_info.cb,
				0,
				row->packet_info.disable_aps_ack,
				0);

	if (zb_err_code != RET_OK) {
		zb_cli_print_error(row->shell, "Can not send ZCL frame",
				   ZB_FALSE);
		/* Invalidate row ctx so that we can reuse it. */
		invalidate_ctx(row);
		zb_buf_free(row->packet_info.buffer);
		return;
	}

	/* Start timeout timer. */
	zb_err_code = ZB_SCHEDULE_APP_ALARM(
			cmd_zb_subscribe_unsubscribe_timeout, row->tsn,
			ZIGBEE_CLI_CONFIGURE_REPORT_RESP_TIMEOUT *
			 ZB_TIME_ONE_SECOND);

	if (zb_err_code != RET_OK) {
		zb_cli_print_error(row->shell,
				   "Unable to schedule timeout timer",
				   ZB_FALSE);
		invalidate_ctx(row);
	}
}

/**@brief Validate and parse input arguments `subscribe` command is called with.
 *        Takes the same input as command handler and if parsed correctly,
 *        fills the `tsn_cli_entry` structure variables.
 */
static int cmd_zb_subscribe_parse_input(size_t argc, char **argv,
					struct tsn_ctx *tsn_cli_entry)
{
	tsn_cli_entry->packet_info.dst_addr_mode =
		parse_address(argv[1], &tsn_cli_entry->packet_info.dst_addr,
			      ADDR_ANY);

	if (tsn_cli_entry->packet_info.dst_addr_mode == ADDR_INVALID) {
		zb_cli_print_error(tsn_cli_entry->shell,
				   "Invalid remote address", ZB_FALSE);
		return -EINVAL;
	}

	if (!zb_cli_sscan_uint8(argv[2],
				&(tsn_cli_entry->packet_info.dst_ep))) {

		zb_cli_print_error(tsn_cli_entry->shell,
				   "Incorrect remote endpoint",
				   ZB_FALSE);
		return -EINVAL;
	}

	if (!parse_hex_u16(argv[3], &(tsn_cli_entry->packet_info.cluster_id))) {
		zb_cli_print_error(tsn_cli_entry->shell, "Incorrect cluster ID",
				   ZB_FALSE);
		return -EINVAL;
	}

	if (!parse_hex_u16(argv[4], &(tsn_cli_entry->packet_info.prof_id))) {
		zb_cli_print_error(tsn_cli_entry->shell, "Incorrect profile ID",
				   ZB_FALSE);
		return -EINVAL;
	}

	if (!parse_hex_u16(argv[5], &(tsn_cli_entry->req.attr_id))) {
		zb_cli_print_error(tsn_cli_entry->shell,
				   "Incorrect attribute ID", ZB_FALSE);
		return -EINVAL;
	}

	if (!zb_cli_sscan_uint8(argv[6], &(tsn_cli_entry->req.attr_type))) {
		zb_cli_print_error(tsn_cli_entry->shell,
				   "Incorrect attribute type", ZB_FALSE);
		return -EINVAL;
	}

	/* Optional parameters parsing. */
	if (argc > 7) {
		if (!zb_cli_sscan_uint(
			argv[7], (uint8_t *)&tsn_cli_entry->req.interval_min,
			2, 10)) {

			zb_cli_print_error(tsn_cli_entry->shell,
					   "Incorrect minimum interval",
					   ZB_FALSE);
			return -EINVAL;
		}
	}

	if (argc > 8) {
		if (!zb_cli_sscan_uint(
			argv[8], (uint8_t *)&tsn_cli_entry->req.interval_max,
			2, 10)) {

			zb_cli_print_error(tsn_cli_entry->shell,
					   "Incorrect maximum interval",
					   ZB_FALSE);
			return -EINVAL;
		}
	}

	return 0;
}

/**@brief Subscribe to the attribute changes on the remote node.
 *
 * @code
 * zcl subscribe on <h:addr> <d:ep> <h:cluster> <h:profile> <h:attr_id>
 *                  <d:attr_type> [<d:min_interval (s)>] [<d:max_interval (s)>]
 * @endcode
 *
 * Enable reporting on the node identified by `addr`, with the endpoint `ep`
 * that uses the profile `profile` of the attribute `attr_id` with the type
 * `attr_type` in the cluster `cluster`.
 *
 * Reports must be generated in intervals not shorter than `min_interval`
 * (1 second by default) and not longer
 * than `max_interval` (60 seconds by default).
 */
int cmd_zb_subscribe_on(const struct shell *shell, size_t argc, char **argv)
{
	int ret_val;
	zb_bufid_t bufid;
	zb_uint8_t *cmd_ptr;
	zb_ret_t zb_err_code;
	struct tsn_ctx *tsn_cli_entry;

	tsn_cli_entry = get_free_tsn_ctx();
	if (!tsn_cli_entry) {
		zb_cli_print_error(shell,
				   "Too many configure reporting requests",
				   ZB_FALSE);
		return -ENOEXEC;
	}

	/* Set default interval values. */
	tsn_cli_entry->req.interval_min =
		ZIGBEE_CLI_CONFIGURE_REPORT_DEFAULT_MIN_INTERVAL;
	tsn_cli_entry->req.interval_max =
		ZIGBEE_CLI_CONFIGURE_REPORT_DEFAULT_MAX_INTERVAL;

	/* Set pointer to the shell to be used by the command handler. */
	tsn_cli_entry->shell = shell;

	ret_val = cmd_zb_subscribe_parse_input(argc, argv, tsn_cli_entry);
	if (ret_val) {
		/* Parsing input arguments failed, error message has been
		 * already printed in the `cmd_zb_subscribe_parse_input`,
		 * so free the ctx.
		 */
		invalidate_ctx(tsn_cli_entry);
		return ret_val;
	}

	/* Make sure ZBOSS buffer API is called safely. */
	zb_osif_disable_all_inter();
	bufid = zb_buf_get_out();
	zb_osif_enable_all_inter();

	if (!bufid) {
		zb_cli_print_error(shell, "Failed to execute command (buf alloc failed)",
				   ZB_FALSE);
		invalidate_ctx(tsn_cli_entry);
		return -ENOEXEC;
	}

	/* Get the ZCL packet sequence number. */
	tsn_cli_entry->tsn = ZCL_CTX().seq_number;

	/* Construct and send request. */
	ZB_ZCL_GENERAL_INIT_CONFIGURE_REPORTING_SRV_REQ(
		bufid, cmd_ptr, ZB_ZCL_ENABLE_DEFAULT_RESPONSE);
	ZB_ZCL_GENERAL_ADD_SEND_REPORT_CONFIGURE_REPORTING_REQ(
		cmd_ptr, tsn_cli_entry->req.attr_id,
		tsn_cli_entry->req.attr_type, tsn_cli_entry->req.interval_min,
		tsn_cli_entry->req.interval_max,
		ZIGBEE_CLI_CONFIGURE_REPORT_DEFAULT_VALUE_CHANGE);

	/* Fill the structure for sending ZCL frame. */
	tsn_cli_entry->packet_info.buffer = bufid;
	tsn_cli_entry->packet_info.ptr = cmd_ptr;
	/* DstAddr, DstAddr Mode and dst endpoint are already set. */
	tsn_cli_entry->packet_info.ep = zb_cli_get_endpoint();
	/* Profile ID and Cluster ID are already set. */
	tsn_cli_entry->packet_info.cb = NULL;
	tsn_cli_entry->packet_info.disable_aps_ack = ZB_FALSE;

	zb_err_code = ZB_SCHEDULE_APP_CALLBACK(send_reporting_frame,
					       (tsn_cli_entry - tsn_ctx));

	if (zb_err_code != RET_OK) {
		zb_cli_print_error(shell,
				   "Couldn't schedule the callback, wait a bit",
				   ZB_FALSE);
		/* Invalidate ctx so that we can reuse it. */
		invalidate_ctx(tsn_cli_entry);

		/* Make sure ZBOSS buffer API is called safely. */
		zb_osif_disable_all_inter();
		zb_buf_free(bufid);
		zb_osif_enable_all_inter();

		return -ENOEXEC;
	}

	return 0;
}

/**@brief Unsubscribe from the attribute changes on the remote node.
 *
 * @code
 * zcl subscribe off <h:addr> <d:ep> <h:cluster> <h:profile> <h:attr_id>
 *                   <d:attr_type> [<d:min_interval (s)>] [<d:max_interval (s)>]
 * @endcode
 *
 * Disable reporting on the node identified by `addr`, with the endpoint `ep`
 * that uses the profile `profile` of the attribute `attr_id` with the type
 * `attr_type` in the cluster `cluster`.
 */
int cmd_zb_subscribe_off(const struct shell *shell, size_t argc, char **argv)
{
	int ret_val;
	zb_bufid_t bufid;
	zb_uint8_t *cmd_ptr;
	zb_ret_t zb_err_code;
	struct tsn_ctx *tsn_cli_entry;

	tsn_cli_entry = get_free_tsn_ctx();
	if (!tsn_cli_entry) {
		zb_cli_print_error(shell,
				   "Too many configure reporting requests",
				   ZB_FALSE);
		return -ENOEXEC;
	}

	/* Set default interval values. */
	tsn_cli_entry->req.interval_min =
		ZIGBEE_CLI_CONFIGURE_REPORT_OFF_MIN_INTERVAL;
	tsn_cli_entry->req.interval_max =
		ZIGBEE_CLI_CONFIGURE_REPORT_OFF_MAX_INTERVAL;

	/* Set pointer to the shell to be used by the command handler. */
	tsn_cli_entry->shell = shell;

	ret_val = cmd_zb_subscribe_parse_input(argc, argv, tsn_cli_entry);
	if (ret_val) {
		/* Parsing input arguments failed, error message has been
		 * already printed in the `cmd_zb_subscribe_parse_input`,
		 * so free the ctx.
		 */
		invalidate_ctx(tsn_cli_entry);
		return ret_val;
	}

	/* Make sure ZBOSS buffer API is called safely. */
	zb_osif_disable_all_inter();
	bufid = zb_buf_get_out();
	zb_osif_enable_all_inter();

	if (!bufid) {
		zb_cli_print_error(shell, "Failed to execute command (buf alloc failed)",
				   ZB_FALSE);
		invalidate_ctx(tsn_cli_entry);
		return -ENOEXEC;
	}

	/* Get the ZCL packet sequence number. */
	tsn_cli_entry->tsn = ZCL_CTX().seq_number;

	/* Construct and send request. */
	ZB_ZCL_GENERAL_INIT_CONFIGURE_REPORTING_SRV_REQ(
		bufid, cmd_ptr, ZB_ZCL_ENABLE_DEFAULT_RESPONSE);
	ZB_ZCL_GENERAL_ADD_SEND_REPORT_CONFIGURE_REPORTING_REQ(
		cmd_ptr, tsn_cli_entry->req.attr_id,
		tsn_cli_entry->req.attr_type, tsn_cli_entry->req.interval_min,
		tsn_cli_entry->req.interval_max,
		ZIGBEE_CLI_CONFIGURE_REPORT_DEFAULT_VALUE_CHANGE);

	/* Fill the structure for sending ZCL frame. */
	tsn_cli_entry->packet_info.buffer = bufid;
	tsn_cli_entry->packet_info.ptr = cmd_ptr;
	/* DstAddr, DstAddr Mode and dst endpoint are already set. */
	tsn_cli_entry->packet_info.ep = zb_cli_get_endpoint();
	/* Profile ID and Cluster ID are already set. */
	tsn_cli_entry->packet_info.cb = NULL;
	tsn_cli_entry->packet_info.disable_aps_ack = ZB_FALSE;

	zb_err_code = ZB_SCHEDULE_APP_CALLBACK(send_reporting_frame,
					       (tsn_cli_entry - tsn_ctx));

	if (zb_err_code != RET_OK) {
		zb_cli_print_error(shell,
				   "Couldn't schedule the callback, wait a bit",
				   ZB_FALSE);
		/* Invalidate ctx so that we can reuse it. */
		invalidate_ctx(tsn_cli_entry);

		/* Make sure ZBOSS buffer API is called safely. */
		zb_osif_disable_all_inter();
		zb_buf_free(bufid);
		zb_osif_enable_all_inter();

		return -ENOEXEC;
	}

	return 0;
}
