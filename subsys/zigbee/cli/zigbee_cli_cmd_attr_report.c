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

#ifndef DEVELOPMENT_TODO
#error "NRF LOG To be done done here, to be decided here"
// #if NRF_LOG_ENABLED
/**@brief Name of the submodule used for logger messaging.
 */
#define NRF_LOG_SUBMODULE_NAME report

NRF_LOG_INSTANCE_REGISTER(ZIGBEE_CLI_LOG_NAME, NRF_LOG_SUBMODULE_NAME,
			  ZIGBEE_CLI_CONFIG_INFO_COLOR,
			  ZIGBEE_CLI_CONFIG_DEBUG_COLOR,
			  ZIGBEE_CLI_CONFIG_LOG_INIT_FILTER_LEVEL,
			  ZIGBEE_CLI_CONFIG_LOG_ENABLED ?
			   ZIGBEE_CLI_CONFIG_LOG_LEVEL : NRF_LOG_SEVERITY_NONE);

/* This structure keeps reference to the logger instance used by this module. */
typedef struct {
	NRF_LOG_INSTANCE_PTR_DECLARE(p_log)
} log_ctx_t;
// #endif /* defined (NRF_LOG_ENABLED) */
#endif

/* This structure allows for binding ZBOSS transaction and CLI object. */
typedef struct {
	const struct shell *shell;
	u8_t               tsn;
	bool               taken;
	bool               is_broadcast;
} tsn_ctx_t;

/* This structure representing all fields required to construct configure
 * reporting requests.
 */
typedef struct {
	zb_uint16_t profile_id;
	zb_uint16_t cluster_id;
	zb_uint16_t attr_id;
	zb_uint8_t  attr_type;
	zb_uint16_t interval_min;
	zb_uint16_t interval_max;
	zb_addr_u   remote_node;
	addr_type_t remote_addr_mode;
	zb_uint8_t  remote_ep;
} configure_reporting_req_t;

#ifndef DEVELOPMENT_TODO
#error "NRF LOG Submodule to be done here"
// #if NRF_LOG_ENABLED
/* Logger instance used by this module. */
static log_ctx_t m_log = {
	NRF_LOG_INSTANCE_PTR_INIT(p_log, ZIGBEE_CLI_LOG_NAME,
				  NRF_LOG_SUBMODULE_NAME)
};
// #endif /* defined (NRF_LOG_ENABLED) */
#endif

static tsn_ctx_t m_tsn_ctx[ZIGBEE_CLI_CONFIGURE_REPORT_TSN];


/**@brief Return a pointer to context with the given transaction
 *        sequence number.
 *
 * @param[in] tsn ZBOSS transaction sequence number
 *
 * @return a pointer to context or NULL if context for given TSN wasn't found.
 */
static tsn_ctx_t * get_ctx_by_tsn(u8_t tsn)
{
	for (u8_t i = 0; i < ARRAY_SIZE(m_tsn_ctx); i++) {
		if ((m_tsn_ctx[i].taken == true) && (m_tsn_ctx[i].tsn == tsn)) {
			return &m_tsn_ctx[i];
		}
	}

	return NULL;
}

/**@brief Get a pointer to a free context.
 *
 * @return a pointer to context structure or NULL if all contexts are taken.
 */
static tsn_ctx_t * get_free_tsn_ctx(void)
{
	for (u8_t i = 0; i < ARRAY_SIZE(m_tsn_ctx); i++) {
		if (!m_tsn_ctx[i].taken) {
			return &m_tsn_ctx[i];
		}
	}

	return NULL;
}

/**
 * Invalidate context.
 *
 * @param[in] p_tsn_ctx a pointer to transaction context.
 */
static void invalidate_ctx(tsn_ctx_t * p_tsn_ctx)
{
	p_tsn_ctx->taken = false;
	p_tsn_ctx->tsn   = 0xFF;
	p_tsn_ctx->shell = NULL;
}

/**@brief Handles timeout error and invalidates configure reporting transaction.
 *
 * @param[in] tsn ZBOSS transaction sequence number
 */
static void cmd_zb_subscribe_unsubscribe_timeout(u8_t tsn)
{
	tsn_ctx_t * p_tsn_ctx = get_ctx_by_tsn(tsn);

	if (!p_tsn_ctx) {
		return;
	}

	print_error(p_tsn_ctx->shell, "Request timed out", ZB_TRUE);
	invalidate_ctx(p_tsn_ctx);
}

/**@brief Print the Configure Reporting Response
 *
 * @param p_tsn_ctx[in]     Pointer to context structure
 * @param bufid[in]         ZBOSS buffer id
 */
static void cmd_zb_subscribe_unsubscribe_cb(tsn_ctx_t * p_tsn_ctx,
					    zb_bufid_t bufid)
{
	zb_ret_t                           zb_err_code;
	zb_zcl_configure_reporting_res_t * p_resp = NULL;
	zb_bool_t                          failed = ZB_FALSE;

	zb_err_code = ZB_SCHEDULE_APP_ALARM_CANCEL(
			cmd_zb_subscribe_unsubscribe_timeout,
			ZB_ALARM_ANY_PARAM);
	if (zb_err_code != RET_OK) {
		print_error(p_tsn_ctx->shell, "Unable to cancel timeout timer",
			    ZB_TRUE);
		goto free_tsn_ctx;
	}

	/* Check if response contains only status code. */
	if (sizeof(zb_zcl_configure_reporting_res_t) > zb_buf_len(bufid)) {
		p_resp = (zb_zcl_configure_reporting_res_t*)zb_buf_begin(bufid);
		if (p_resp->status == ZB_ZCL_STATUS_SUCCESS) {
			print_done(p_tsn_ctx->shell, ZB_FALSE);
		} else {
			shell_error(p_tsn_ctx->shell, "Error: Unable to configure reporting. Status: %d",
				    p_resp->status);
		}
		goto free_tsn_ctx;
	}

	/* Received a full Configure Reporting Response frame. */
	ZB_ZCL_GENERAL_GET_NEXT_CONFIGURE_REPORTING_RES(bufid, p_resp);
	if (p_resp == NULL) {
		print_error(p_tsn_ctx->shell, "Unable to parse configure reporting response",
			    ZB_TRUE);
		goto free_tsn_ctx;
	}

	while (p_resp != NULL) {
		if (p_resp->status == ZB_ZCL_STATUS_SUCCESS) {
			switch (p_resp->direction) {
			case ZB_ZCL_CONFIGURE_REPORTING_SEND_REPORT:
				shell_print(p_tsn_ctx->shell,
					    "Local subscription to attribute ID %hx updated",
					    p_resp->attr_id);
				break;

			case ZB_ZCL_CONFIGURE_REPORTING_RECV_REPORT:
				shell_print(p_tsn_ctx->shell,
					    "Remote node subscription to receive attribute ID %hx updated",
					    p_resp->attr_id);
				break;

			default:
				shell_error(p_tsn_ctx->shell,
					    "Error: Unknown reporting configuration direction for attribute %hx",
					    p_resp->attr_id);
				failed = ZB_TRUE;
				break;
			}
		} else {
			shell_error(p_tsn_ctx->shell,
				    "Error: Unable to configure attribute %hx reporting. Status: %hd",
				    p_resp->attr_id, p_resp->status);
			failed = ZB_TRUE;
		}
		ZB_ZCL_GENERAL_GET_NEXT_CONFIGURE_REPORTING_RES(bufid, p_resp);
	}

	if (failed == ZB_TRUE) {
		print_error(p_tsn_ctx->shell, "One or more attributes reporting were not configured successfully",
			    ZB_TRUE);
	} else {
		print_done(p_tsn_ctx->shell, ZB_FALSE);
	}

free_tsn_ctx:
	invalidate_ctx(p_tsn_ctx);
	zb_buf_free(bufid);
}

/**@brief Print the Report Attribute Command
 *
 * @param p_zcl_hdr[in]     Pointer to parsed ZCL header
 * @param bufid[in]         ZBOSS buffer id
 */
static void print_attr_update(zb_zcl_parsed_hdr_t * p_zcl_hdr, zb_bufid_t bufid)
{
	zb_zcl_report_attr_req_t *p_attr_resp   = NULL;
	zb_zcl_addr_t remote_node_data =
		p_zcl_hdr->addr_data.common_data.source;
	int bytes_written = 0;
	char print_buf[255];

	if (remote_node_data.addr_type == ZB_ZCL_ADDR_TYPE_SHORT) {
#ifndef DEVELOPMENT_TODO
		NRF_LOG_INST_INFO(m_log.p_log, "Received value updates from the remote node 0x%04x", remote_node_data.u.short_addr);
#endif
	} else {
		bytes_written = ieee_addr_to_str(print_buf, sizeof(print_buf),
						 remote_node_data.u.ieee_addr);
		if (bytes_written < 0) {
#ifndef DEVELOPMENT_TODO
			NRF_LOG_INST_INFO(m_log.p_log, "Received value updates from the remote node (unknown address)");
#endif
		} else {
#ifndef DEVELOPMENT_TODO
			NRF_LOG_INST_INFO(m_log.p_log, "Received value updates from the remote node 0x%s", nrf_log_push(print_buf));
#endif
		}
	}

	/* Get the contents of Read Attribute Response frame. */
	ZB_ZCL_GENERAL_GET_NEXT_REPORT_ATTR_REQ(bufid, p_attr_resp);
	bytes_written = 0;
	while (p_attr_resp != NULL) {
		bytes_written = zcl_attr_to_str(&print_buf[bytes_written],
						(sizeof(print_buf) -
						 bytes_written),
						p_attr_resp->attr_type,
						p_attr_resp->attr_value);

		if (bytes_written < 0) {
#ifndef DEVELOPMENT_TODO
			NRF_LOG_ERROR("    Unable to print updated attribute value");
#endif
		} else {
#ifndef DEVELOPMENT_TODO
			NRF_LOG_INST_INFO(m_log.p_log, "    Profile: 0x%04x Cluster: 0x%04x Attribute: 0x%04x Type: %hu Value: %s", p_zcl_hdr->profile_id, p_zcl_hdr->cluster_id, p_attr_resp->attr_id, p_attr_resp->attr_type, nrf_log_push(print_buf));
#endif
		}

		ZB_ZCL_GENERAL_GET_NEXT_REPORT_ATTR_REQ(bufid, p_attr_resp);
	}
}

/**@brief The Handler to 'intercept' every frame coming to the endpoint
 *
 * @param bufid[in]  ZBOSS buffer id
 *
 * @returns ZB_TRUE if ZCL command was processed.
 */
static zb_uint8_t cli_agent_ep_handler_report(zb_bufid_t bufid)
{
	zb_zcl_parsed_hdr_t *p_cmd_info = ZB_BUF_GET_PARAM(bufid,
							   zb_zcl_parsed_hdr_t);
	tsn_ctx_t           *p_tsn_ctx;

	if (p_cmd_info->cmd_id == ZB_ZCL_CMD_REPORT_ATTRIB) {
		print_attr_update(p_cmd_info, bufid);
		zb_buf_free(bufid);
		return ZB_TRUE;
	} else if (p_cmd_info->cmd_id == ZB_ZCL_CMD_CONFIG_REPORT_RESP) {
		/* Find command context by ZCL sequence number. */
		p_tsn_ctx = get_ctx_by_tsn(p_cmd_info->seq_number);
		if (p_tsn_ctx != NULL) {
			cmd_zb_subscribe_unsubscribe_cb(p_tsn_ctx, bufid);
			return ZB_TRUE;
		}
	}

	return ZB_FALSE;
}

/**@brief Subscribe to the attribute changes on the remote node.
 *
 * @code
 * zcl subscribe {on, off} <h:addr> <d:ep> <h:cluster> <h:profile>
 *                         <h:attr_id> <d:attr_type>
 *                         [<d:min_interval (s)>] [<d:max_interval (s)>]
 * @endcode
 *
 * Enable or disable reporting on the node identified by `addr`,
 * with the endpoint `ep` that uses the profile `profile`
 * of the attribute `attr_id` with the type `attr_type`
 * in the cluster `cluster`.
 *
 * Reports must be generated in intervals not shorter than `min_interval`
 * (1 second by default) and not longer
 * than `max_interval` (60 seconds by default).
 */
int cmd_zb_subscribe(const struct shell *shell, size_t argc, char **argv)
{
	configure_reporting_req_t   req;
	tsn_ctx_t                 * p_tsn_cli;
	zb_bufid_t                  bufid;
	zb_uint8_t                * p_cmd_ptr;
	zb_ret_t                    zb_err_code;
	zb_bool_t                   subscribe;

	subscribe = (strcmp(argv[0], "on") == 0) ? ZB_TRUE : ZB_FALSE;

	if ((((argc < 7) || (argc > 9)) && (subscribe == ZB_TRUE)) ||
	    ((argc != 7) && (subscribe == ZB_FALSE))) {
		print_error(shell, "Incorrect number of arguments", ZB_FALSE);
		return -EINVAL;
	}

	req.remote_addr_mode = parse_address(argv[1], &req.remote_node,
					     ADDR_ANY);

	if (req.remote_addr_mode == ADDR_INVALID) {
		print_error(shell, "Invalid remote address", ZB_FALSE);
		return -EINVAL;
	}

	if (!sscan_uint8(argv[2], &(req.remote_ep))) {
		print_error(shell, "Incorrect remote endpoint", ZB_FALSE);
		return -EINVAL;
	}

	if (!parse_hex_u16(argv[3], &(req.cluster_id))) {
		print_error(shell, "Incorrect cluster ID", ZB_FALSE);
		return -EINVAL;
	}

	if (!parse_hex_u16(argv[4], &(req.profile_id))) {
		print_error(shell, "Incorrect profile ID", ZB_FALSE);
		return -EINVAL;
	}

	if (!parse_hex_u16(argv[5], &(req.attr_id))) {
		print_error(shell, "Incorrect attribute ID", ZB_FALSE);
		return -EINVAL;
	}

	if (!sscan_uint8(argv[6], &(req.attr_type))) {
		print_error(shell, "Incorrect attribute type", ZB_FALSE);
		return -EINVAL;
	}

	/* Optional parameters parsing. */
	if (subscribe == ZB_TRUE) {
		req.interval_min =
			ZIGBEE_CLI_CONFIGURE_REPORT_DEFAULT_MIN_INTERVAL;
		req.interval_max =
			ZIGBEE_CLI_CONFIGURE_REPORT_DEFAULT_MAX_INTERVAL;
	} else {
		req.interval_min = ZIGBEE_CLI_CONFIGURE_REPORT_OFF_MIN_INTERVAL;
		req.interval_max = ZIGBEE_CLI_CONFIGURE_REPORT_OFF_MAX_INTERVAL;
	}

	if (argc > 7) {
		req.interval_min = strtoul(argv[7], NULL, 16);
		if ((argv[7][0] == '0') && ((argv[7][1] == 'x') ||
		    (argv[7][1] == 'X'))) {
			print_error(shell, "Incorrect minimum interval",
				    ZB_FALSE);
			return -EINVAL;
		}
	}

	if (argc > 8) {
		req.interval_max = strtoul(argv[8], NULL, 16);
		if ((argv[8][0] == '0') && ((argv[8][1] == 'x') ||
		    (argv[8][1] == 'X'))) {
			print_error(shell, "Incorrect maximum interval",
				    ZB_FALSE);
			return -EINVAL;
		}
	}

	bufid = zb_buf_get_out();
	if (!bufid) {
		print_error(shell,
			    "Failed to execute command (buf alloc failed)",
			    ZB_FALSE);
		return -ENOEXEC;
	}

	p_tsn_cli = get_free_tsn_ctx();
	if (!p_tsn_cli) {
		print_error(shell, "Too many configure reporting requests",
			    ZB_FALSE);
		zb_buf_free(bufid);
		return -ENOEXEC;
	}

	/* Configure new tsn context. */
	p_tsn_cli->taken = true;
	p_tsn_cli->shell = shell;
	p_tsn_cli->tsn   = ZCL_CTX().seq_number;

	/* Construct and send request. */
	ZB_ZCL_GENERAL_INIT_CONFIGURE_REPORTING_SRV_REQ(
		bufid, p_cmd_ptr, ZB_ZCL_ENABLE_DEFAULT_RESPONSE);
	ZB_ZCL_GENERAL_ADD_SEND_REPORT_CONFIGURE_REPORTING_REQ(
		p_cmd_ptr, req.attr_id, req.attr_type, req.interval_min,
		req.interval_max,
		ZIGBEE_CLI_CONFIGURE_REPORT_DEFAULT_VALUE_CHANGE);
	ZB_ZCL_GENERAL_SEND_CONFIGURE_REPORTING_REQ(
		bufid, p_cmd_ptr, req.remote_node, req.remote_addr_mode,
		req.remote_ep, zb_get_cli_endpoint(), req.profile_id,
		req.cluster_id, NULL);

	/* Start timeout timer. */
	zb_err_code = ZB_SCHEDULE_APP_ALARM(
			cmd_zb_subscribe_unsubscribe_timeout, p_tsn_cli->tsn,
			ZIGBEE_CLI_CONFIGURE_REPORT_RESP_TIMEOUT *
			 ZB_TIME_ONE_SECOND);
	if (zb_err_code != RET_OK) {
		print_error(shell, "Unable to schedule timeout timer",
			    ZB_FALSE);
		invalidate_ctx(p_tsn_cli);
	}
	return 0;
}

/**@brief Endpoint handlers
 */
#ifndef DEVELOPMENT_TODO
#error "Endpoint handler to be done here"
NRF_ZIGBEE_EP_HANDLER_REGISTER(report, cli_agent_ep_handler_report);
#endif

/** @} */
