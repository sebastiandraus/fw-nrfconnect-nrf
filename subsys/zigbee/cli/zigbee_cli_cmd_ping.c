/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stdlib.h>
#include <shell/shell.h>

#include <zb_nrf_platform.h>
#include <zb_error_handler.h>
#include "zigbee_cli.h"
#include "zigbee_cli_ping.h"
#include "zigbee_cli_utils.h"

/** @brief ZCL Frame control field of Zigbee PING commands.
 */

#define ZIGBEE_PING_FRAME_CONTROL_FIELD 0x11

#define LOG_SUBMODULE_NAME ping

LOG_MODULE_REGISTER(LOG_SUBMODULE_NAME, CONFIG_ZIGBEE_SHELL_LOG_LEVEL);

/**@brief The row of the table which holds the replies which are to be sent.
 *
 * @details We use the table to temporarily store the parameters of the ping
 *          reply while it is traversing the ZBOSS callback system.
 *          The key parameter is the sequence number.
 */
struct ping_reply {
	bool taken;
	zb_uint8_t ping_seq;
	zb_uint8_t count;
	zb_uint8_t send_ack;
	const struct shell *shell;
	struct zcl_packet_info packet_info;
};

static struct ping_request ping_request_table[PING_TABLE_SIZE];
static struct ping_reply ping_reply_table[PING_TABLE_SIZE];
static uint8_t ping_seq_num;
static ping_time_cb_t ping_ind_cb;

static zb_uint32_t get_request_duration(struct ping_request *ping_req_ctx);

struct ping_request *zb_ping_acquire_request(void)
{
	int i;

	for (i = 0; i < PING_TABLE_SIZE; i++) {
		if (ping_request_table[i].taken == false) {
			ping_request_table[i].taken = true;
			return &(ping_request_table[i]);
		}
	}

	return NULL;
}

void zb_ping_release_request(struct ping_request *ping_reply_ctx)
{
	if (ping_reply_ctx != NULL) {
		ping_reply_ctx->taken = false;
		ZB_MEMSET(ping_reply_ctx, 0x00, sizeof(struct ping_request));
	}
}

/**@brief Acquire ping reply context.
 *
 * @return  Pointer to a free ping reply context or NULL on failure.
 */
static struct ping_reply *ping_aquire_reply(void)
{
	int i;

	for (i = 0; i < PING_TABLE_SIZE; i++) {
		if (ping_reply_table[i].taken == false) {
			ping_reply_table[i].taken = true;
			return &(ping_reply_table[i]);
		}
	}

	return NULL;
}

/**@brief Release ping reply context.
 *
 * @param ping_reply_ctx Pointer to the reply context structure to release.
 */
void ping_release_reply(struct ping_reply *ping_reply_ctx)
{
	if (ping_reply_ctx != NULL) {
		ping_reply_ctx->taken = false;
		ZB_MEMSET(ping_reply_ctx, 0x00, sizeof(struct ping_reply));
	}
}

/**@brief Invalidate Ping Request row after the timeout - ZBOSS callback
 *
 * @param row     Number of row to invalidate
 */
static void invalidate_row_cb(zb_uint8_t row)
{
	struct ping_request *ping_req_ctx = &(ping_request_table[row]);
	uint32_t delay_ms = get_request_duration(ping_req_ctx);

	/* Inform user about timeout event. */
	if (ping_req_ctx->cb) {
		ping_req_ctx->cb(PING_EVT_FRAME_TIMEOUT, delay_ms,
				 ping_req_ctx);
	}

	zb_ping_release_request(ping_req_ctx);
}

/**@brief Get the first row with request sent to addr_short.
 *
 * @param addr_short  Short network address to look for.
 *
 * @return  Pointer to the ping request context, NULL if none.
 */
static struct ping_request *find_request_by_short(zb_uint16_t addr_short)
{
	int i;
	zb_addr_u req_remote_addr;

	for (i = 0; i < PING_TABLE_SIZE; i++) {
		req_remote_addr = ping_request_table[i].packet_info.dst_addr;

		if (ping_request_table[i].taken == true) {
			if (ping_request_table[i].packet_info.dst_addr_mode ==
			    ZB_APS_ADDR_MODE_16_ENDP_PRESENT) {
				if (req_remote_addr.addr_short == addr_short) {
					return &(ping_request_table[i]);
				}
			} else {
				if (zb_address_short_by_ieee(
					req_remote_addr.addr_long) ==
					 addr_short) {

					return &(ping_request_table[i]);
				}
			}
		}
	}

	return NULL;
}

/**@brief Get the taken row with the selected seq_num, return NULL if none
 *
 * @param seqnum Sequence Number to look for
 */
static struct ping_request *find_request_by_sn(zb_uint8_t seqnum)
{
	int i;

	for (i = 0; i < PING_TABLE_SIZE; i++) {
		if (ping_request_table[i].taken == true) {
			if (ping_request_table[i].ping_seq == seqnum) {
				return &ping_request_table[i];
			}
		}
	}

	return NULL;
}

/**@brief Get row number for the ping request.
 *
 * @param[in] ping_req_ctx Pointer to the ping request context.
 *
 * @return Row number, -1 if not found.
 */
static zb_int8_t get_request_row(struct ping_request *ping_req_ctx)
{
	if (ping_req_ctx != NULL) {
		return (ping_req_ctx - ping_request_table);
	}

	return -1;
}

static void zb_zcl_send_ping_frame(zb_uint8_t idx, zb_uint16_t is_request)
{
	zb_ret_t zb_err_code;
	struct zcl_packet_info *packet_info;

	if (is_request) {
		packet_info = &(ping_request_table[idx].packet_info);

		/* Capture the sending time. */
		ping_request_table[idx].sent_time = k_uptime_ticks();
	} else {
		packet_info = &(ping_reply_table[idx].packet_info);
	}

	/* Send the actual frame. */
	zb_err_code = zb_zcl_finish_and_send_packet_new(
				packet_info->buffer,
				packet_info->ptr,
				&(packet_info->dst_addr),
				packet_info->dst_addr_mode,
				packet_info->dst_ep,
				packet_info->ep,
				packet_info->prof_id,
				packet_info->cluster_id,
				packet_info->cb,
				0,
				packet_info->disable_aps_ack,
				0);

	if (is_request) {
		struct ping_request *ping_req_ctx = &ping_request_table[idx];

		if (zb_err_code != RET_OK) {
			zb_cli_print_error(ping_req_ctx->shell,
					   "Can not send zcl frame", ZB_FALSE);
			zb_buf_free(packet_info->buffer);
			zb_ping_release_request(ping_req_ctx);
			return;
		}

		zb_err_code = ZB_SCHEDULE_APP_ALARM(
					invalidate_row_cb,
					idx,
					ZB_MILLISECONDS_TO_BEACON_INTERVAL(
						ping_req_ctx->timeout_ms));
		if (zb_err_code != RET_OK) {
			zb_cli_print_error(ping_req_ctx->shell,
					   "Can not schedule timeout alarm.",
					   ZB_FALSE);
			zb_ping_release_request(ping_req_ctx);
			return;
		}

		if (ping_req_ctx->cb) {
			uint32_t time_diff = get_request_duration(ping_req_ctx);

			ping_req_ctx->cb(PING_EVT_FRAME_SCHEDULED, time_diff,
					 ping_req_ctx);
		}
	} else {
		if (zb_err_code != RET_OK) {
			zb_cli_print_error(ping_reply_table[idx].shell,
					   "Can not send zcl frame", ZB_FALSE);
			zb_buf_free(packet_info->buffer);
		}
		/* We don't need the row in this table anymore,
		 * since we're not expecting any reply to a Ping Reply.
		 */
		ping_release_reply(&(ping_reply_table[idx]));
	}
}

/**@brief Get time difference, in miliseconds between ping request identified
 *        by row number and current time.
 *
 * @param[in] ping_req_ctx  Pointer to the ping request structure,
 *                          from which the time difference should be calculated.
 *
 * @return  Time difference in miliseconds.
 */
static zb_uint32_t get_request_duration(struct ping_request *ping_req_ctx)
{
	uint32_t time_diff_ms;
	int32_t time_diff_ticks;

	/* Calculate the time difference between request being sent
	 * and reply being received.
	 */
	time_diff_ticks = k_uptime_ticks() - ping_req_ctx->sent_time;
	time_diff_ms = k_ticks_to_ms_near32(time_diff_ticks);

	return time_diff_ms;
}

static void frame_acked_cb(zb_bufid_t bufid)
{
	if (bufid) {
		zb_buf_free(bufid);
	}
}

/**@brief Default handler for incoming ping request APS acknowledgments.
 *
 * @details  If there is a user callback defined for the acknowledged request,
 *           the callback with PING_EVT_ACK_RECEIVED event will be called.
 *
 * @param[in] bufid  Reference to a ZBOSS buffer containing APC ACK data,
 */
static void dispatch_user_callback(zb_bufid_t bufid)
{
	zb_uint16_t short_addr;
	zb_ret_t zb_err_code = RET_OK;
	struct ping_request *ping_req_ctx = NULL;
	zb_zcl_command_send_status_t *ping_cmd_status;

	if (bufid == 0) {
		return;
	}

	ping_cmd_status = ZB_BUF_GET_PARAM(bufid,
					   zb_zcl_command_send_status_t);

	if (ping_cmd_status->dst_addr.addr_type == ZB_ZCL_ADDR_TYPE_SHORT) {
		short_addr = ping_cmd_status->dst_addr.u.short_addr;
	} else if (ping_cmd_status->dst_addr.addr_type ==
		   ZB_ZCL_ADDR_TYPE_IEEE) {
		short_addr = zb_address_short_by_ieee(
				ping_cmd_status->dst_addr.u.ieee_addr);
	} else {
		LOG_ERR("Ping request acknowledged with an unknown destination address type: %d",
			ping_cmd_status->dst_addr.addr_type);
		zb_buf_free(bufid);
		return;
	}

	ping_req_ctx = find_request_by_short(short_addr);

	if (ping_req_ctx != NULL) {
		uint32_t delay_ms = get_request_duration(ping_req_ctx);

		if (ping_cmd_status->status == RET_OK) {
			/* Inform user about ACK reception. */
			if (ping_req_ctx->cb) {
				if (ping_req_ctx->request_ack == 0) {
					ping_req_ctx->cb(
						PING_EVT_FRAME_SENT,
						delay_ms, ping_req_ctx);
				} else {
					ping_req_ctx->cb(
						PING_EVT_ACK_RECEIVED,
						delay_ms, ping_req_ctx);
				}
			}

			/* If only ACK was requested, cancel ongoing alarm. */
			if (ping_req_ctx->request_echo == 0) {
				zb_err_code = ZB_SCHEDULE_APP_ALARM_CANCEL(
						invalidate_row_cb,
						get_request_row(ping_req_ctx));
				if (zb_err_code == RET_OK) {
					zb_ping_release_request(ping_req_ctx);
				}
			}
		} else {
			LOG_ERR("Ping request returned error status: %d",
				ping_cmd_status->status);
		}
	} else {
		LOG_WRN("Unknown ping command callback called with status: %d",
			ping_cmd_status->status);
	}

	zb_buf_free(bufid);
}

/**@brief  Default ping event handler. Prints out measured time on the CLI
 *         and exits.
 *
 * @param[in] evt           Type of received ping acknowledgment
 * @param[in] delay_ms      Time, in miliseconds, between ping request
 *                          and the event.
 * @param[in] ping_req_ctx  Pointer to the ongoing ping request context
 *                          structure.
 */
static void ping_cli_evt_handler(enum ping_time_evt evt, zb_uint32_t delay_ms,
				 struct ping_request *ping_req_ctx)
{
	switch (evt) {
	case PING_EVT_FRAME_SCHEDULED:
		break;

	case PING_EVT_FRAME_TIMEOUT:
		shell_error(ping_req_ctx->shell,
			    "Error: Request timed out after %ld ms.", delay_ms);
		break;

	case PING_EVT_ECHO_RECEIVED:
		shell_print(ping_req_ctx->shell, "Ping time: %ld ms", delay_ms);
		zb_cli_print_done(ping_req_ctx->shell, ZB_FALSE);
		break;

	case PING_EVT_ACK_RECEIVED:
		if (ping_req_ctx->request_echo == 0) {
			shell_print(ping_req_ctx->shell, "Ping time: %ld ms",
				    delay_ms);
			zb_cli_print_done(ping_req_ctx->shell, ZB_FALSE);
		}
		break;

	case PING_EVT_FRAME_SENT:
		if ((ping_req_ctx->request_echo == 0) &&
		    (ping_req_ctx->request_ack == 0)) {
			zb_cli_print_done(ping_req_ctx->shell, ZB_FALSE);
		}
		break;

	case PING_EVT_ERROR:
		zb_cli_print_error(ping_req_ctx->shell,
				   "Unable to send ping request", ZB_FALSE);
		break;

	default:
		LOG_ERR("Unknown ping event received: %d", evt);
		break;
	}
}

void zb_ping_set_ping_indication_cb(ping_time_cb_t cb)
{
	ping_ind_cb = cb;
}

void ping_request_send(struct ping_request *ping_req_ctx)
{
	zb_ret_t zb_err_code;
	zb_bufid_t bufid;
	zb_uint8_t *cmd_buf_ptr;
	zb_uint8_t cli_ep = zb_cli_get_endpoint();

	if (ping_req_ctx->count > PING_MAX_LENGTH) {
		if (ping_req_ctx->cb) {
			ping_req_ctx->cb(PING_EVT_ERROR, 0, ping_req_ctx);
		}

		return;
	}

	/* Make sure ZBOSS buffer API is called safely. */
	zb_osif_disable_all_inter();
	bufid = zb_buf_get_out();
	zb_osif_enable_all_inter();

	if (!bufid) {
		if (ping_req_ctx->cb) {
			ping_req_ctx->cb(PING_EVT_ERROR, 0, ping_req_ctx);
		}
		return;
	}

	/* Ping Frame is constructed by 'overloading' the common ZCL frame.
	 * Basically every frame which comes addressed to
	 * the PING_CUSTOM_CLUSTER is considered a Ping Frame. The FCF is being
	 * set to 0x00, the sequence number field is being used as
	 * a Ping Sequence Number, while the Command field is used to
	 * distinguish request/reply. The farther payload of the ping is filled
	 * with bytes PING_ECHO_REQUEST_BYTE/PING_ECHO_REPLY_BYTE.
	 */
	cmd_buf_ptr = ZB_ZCL_START_PACKET(bufid);
	*(cmd_buf_ptr++) = ZIGBEE_PING_FRAME_CONTROL_FIELD;
	/* Sequence Number Field. */
	*(cmd_buf_ptr++) = ping_seq_num;

	/* Fill Command Field. */
	if ((ping_req_ctx->request_echo) && (ping_req_ctx->request_ack)) {
		*(cmd_buf_ptr++) = PING_ECHO_REQUEST;
	} else if ((ping_req_ctx->request_echo) &&
		   (!ping_req_ctx->request_ack)) {
		*(cmd_buf_ptr++) = PING_ECHO_NO_ACK_REQUEST;
	} else {
		*(cmd_buf_ptr++) = PING_NO_ECHO_REQUEST;
	}

	memset(cmd_buf_ptr, PING_ECHO_REQUEST_BYTE, ping_req_ctx->count);
	cmd_buf_ptr += ping_req_ctx->count;
	ping_req_ctx->ping_seq = ping_seq_num;
	ping_seq_num++;

	/* Schedle frame to send. */
	ping_req_ctx->packet_info.buffer = bufid;
	ping_req_ctx->packet_info.ptr = cmd_buf_ptr;
	/* DstAddr and Addr mode already set. */
	ping_req_ctx->packet_info.dst_ep = cli_ep;
	ping_req_ctx->packet_info.ep = cli_ep;
	ping_req_ctx->packet_info.prof_id = ZB_AF_HA_PROFILE_ID;
	ping_req_ctx->packet_info.cluster_id = PING_CUSTOM_CLUSTER;
	ping_req_ctx->packet_info.cb = dispatch_user_callback;
	ping_req_ctx->packet_info.disable_aps_ack =
		(ping_req_ctx->request_ack ? ZB_FALSE : ZB_TRUE);

	zb_err_code = ZB_SCHEDULE_APP_CALLBACK2(zb_zcl_send_ping_frame,
						get_request_row(ping_req_ctx),
						ZB_TRUE);
	if (zb_err_code != RET_OK) {
		zb_cli_print_error(ping_req_ctx->shell,
				   "Can not schedule zcl frame.", ZB_FALSE);

		/* Make sure ZBOSS buffer API is called safely. */
		zb_osif_disable_all_inter();
		zb_buf_free(ping_req_ctx->packet_info.buffer);
		zb_osif_enable_all_inter();

		zb_ping_release_request(ping_req_ctx);
		return;
	}
}

/**@brief Actually construct the Ping Reply frame and send it.
 *
 * @param ping_reply_ctx  Pointer to the ping reply context structure.
 */
static void ping_reply_send(struct ping_reply *ping_reply_ctx)
{
	zb_bufid_t bufid;
	zb_uint8_t *cmd_buf_ptr;
	zb_uint8_t cli_ep = zb_cli_get_endpoint();
	zb_ret_t zb_err_code;

	/* Make sure ZBOSS buffer API is called safely. */
	zb_osif_disable_all_inter();
	bufid = zb_buf_get_out();
	zb_osif_enable_all_inter();

	if (!bufid) {
		LOG_WRN("Drop ping request due to the lack of output buffers");
		ping_release_reply(ping_reply_ctx);
		return;
	}
	LOG_DBG("Send ping reply");

	cmd_buf_ptr = ZB_ZCL_START_PACKET(bufid);
	*(cmd_buf_ptr++) = ZIGBEE_PING_FRAME_CONTROL_FIELD;
	*(cmd_buf_ptr++) = ping_reply_ctx->ping_seq;
	*(cmd_buf_ptr++) = PING_ECHO_REPLY;
	memset(cmd_buf_ptr, PING_ECHO_REPLY_BYTE, ping_reply_ctx->count);
	cmd_buf_ptr += ping_reply_ctx->count;

	/* Schedule frame to send. */
	ping_reply_ctx->packet_info.buffer = bufid;
	ping_reply_ctx->packet_info.ptr = cmd_buf_ptr;
	/* DstAddr is already set. */
	ping_reply_ctx->packet_info.dst_addr_mode =
		ZB_APS_ADDR_MODE_16_ENDP_PRESENT;
	ping_reply_ctx->packet_info.dst_ep = cli_ep;
	ping_reply_ctx->packet_info.ep = cli_ep;
	ping_reply_ctx->packet_info.prof_id = ZB_AF_HA_PROFILE_ID;
	ping_reply_ctx->packet_info.cluster_id = PING_CUSTOM_CLUSTER;
	ping_reply_ctx->packet_info.cb = frame_acked_cb;
	ping_reply_ctx->packet_info.disable_aps_ack =
		(ping_reply_ctx->send_ack ? ZB_FALSE : ZB_TRUE);

	zb_err_code = ZB_SCHEDULE_APP_CALLBACK2(zb_zcl_send_ping_frame,
						(ping_reply_ctx -
						 ping_reply_table),
						ZB_FALSE);
	if (zb_err_code != RET_OK) {
		zb_cli_print_error(ping_reply_ctx->shell,
				   "Can not schedule zcl frame.", ZB_FALSE);

		/* Make sure ZBOSS buffer API is called safely. */
		zb_osif_disable_all_inter();
		zb_buf_free(ping_reply_ctx->packet_info.buffer);
		zb_osif_enable_all_inter();

		ping_release_reply(ping_reply_ctx);
	}
}

/**@brief Indicate ping request reception.
 *
 * @param zcl_cmd_bufid  Zigbee buffer id with the received ZCL packet.
 */
static void ping_req_indicate(zb_bufid_t zcl_cmd_bufid)
{
	struct ping_request tmp_request;
	zb_zcl_addr_t remote_node_addr;
	zb_zcl_parsed_hdr_t *zcl_hdr = ZB_BUF_GET_PARAM(zcl_cmd_bufid,
							zb_zcl_parsed_hdr_t);

	remote_node_addr = zcl_hdr->addr_data.common_data.source;

	if (ping_ind_cb == NULL) {
		return;
	}

	memset(&tmp_request, 0, sizeof(struct ping_request));

	switch (zcl_hdr->cmd_id) {
	case PING_ECHO_REQUEST:
		tmp_request.request_echo = 1;
		tmp_request.request_ack = 1;
		break;

	case PING_ECHO_NO_ACK_REQUEST:
		tmp_request.request_echo = 1;
		break;

	case PING_NO_ECHO_REQUEST:
		break;

	default:
		/* Received frame is not a ping request. */
		return;
	}

	tmp_request.taken = true;
	tmp_request.ping_seq = zcl_hdr->seq_number;
	tmp_request.count = zb_buf_len(zcl_cmd_bufid);
	tmp_request.sent_time = k_uptime_ticks();

	if (remote_node_addr.addr_type != ZB_ZCL_ADDR_TYPE_SHORT) {
		LOG_INF("Ping request received, but indication will not be generated due to the unsupported address type.");
		/* Not supported. */
		return;
	}
	tmp_request.packet_info.dst_addr_mode =
		ZB_APS_ADDR_MODE_16_ENDP_PRESENT;
	tmp_request.packet_info.dst_addr.addr_short =
		remote_node_addr.u.short_addr;

	ping_ind_cb(PING_EVT_REQUEST_RECEIVED,
		    k_ticks_to_us_near32(tmp_request.sent_time), &tmp_request);
}

/**@brief The Handler to 'intercept' every frame coming to the endpoint.
 *
 * @param bufid    Reference to a ZBOSS buffer
 */
zb_uint8_t cli_agent_ep_handler_ping(zb_bufid_t bufid)
{
	zb_zcl_addr_t remote_node_addr;
	zb_zcl_parsed_hdr_t *zcl_hdr = ZB_BUF_GET_PARAM(bufid,
							zb_zcl_parsed_hdr_t);
	zb_uint32_t time_diff;

	remote_node_addr = zcl_hdr->addr_data.common_data.source;

	if ((zcl_hdr->cluster_id != PING_CUSTOM_CLUSTER) ||
	    (zcl_hdr->profile_id != ZB_AF_HA_PROFILE_ID)) {
		return ZB_FALSE;
	}

	LOG_DBG("New ping frame received, bufid: %d", bufid);
	ping_req_indicate(bufid);

	if (zcl_hdr->cmd_id == PING_ECHO_REPLY) {
		zb_uint16_t remote_short_addr = 0x0000;

		/* We have our ping reply. */
		struct ping_request *ping_req_ctx = find_request_by_sn(
							zcl_hdr->seq_number);
		if (ping_req_ctx == NULL) {
			return ZB_FALSE;
		}

		if (ping_req_ctx->packet_info.dst_addr_mode ==
		    ZB_APS_ADDR_MODE_16_ENDP_PRESENT) {
			remote_short_addr =
				ping_req_ctx->packet_info.dst_addr.addr_short;
		} else {
			remote_short_addr = zb_address_short_by_ieee(
				ping_req_ctx->packet_info.dst_addr.addr_long);
		}

		if (remote_node_addr.addr_type != ZB_ZCL_ADDR_TYPE_SHORT) {
			return ZB_FALSE;
		}
		if (remote_short_addr != remote_node_addr.u.short_addr) {
			return ZB_FALSE;
		}

		/* Catch the timer value. */
		time_diff = get_request_duration(ping_req_ctx);

		/* Cancel the ongoing alarm which was to erase the row ... */
		zb_ret_t zb_err_code = ZB_SCHEDULE_APP_ALARM_CANCEL(
						invalidate_row_cb,
						get_request_row(ping_req_ctx));
		ZB_ERROR_CHECK(zb_err_code);

		/* Call callback function in order to indicate
		 * echo response reception.
		 */
		if (ping_req_ctx->cb) {
			ping_req_ctx->cb(PING_EVT_ECHO_RECEIVED, time_diff,
					 ping_req_ctx);
		}

		/* ... and erase it manually. */
		if (zb_err_code == RET_OK) {
			zb_ping_release_request(ping_req_ctx);
		}

	} else if ((zcl_hdr->cmd_id == PING_ECHO_REQUEST) ||
		   (zcl_hdr->cmd_id == PING_ECHO_NO_ACK_REQUEST)) {

		zb_uint8_t len = zb_buf_len(bufid);
		struct ping_reply *ping_reply_ctx = ping_aquire_reply();

		if (ping_reply_ctx == NULL) {
			LOG_WRN("Cannot obtain new row for incoming ping request");
			return ZB_FALSE;
		}

		/* Save the Ping Reply information in the table and schedule
		 * a sending function.
		 */
		ping_reply_ctx->count = len;
		ping_reply_ctx->ping_seq = zcl_hdr->seq_number;

		if (zcl_hdr->cmd_id == PING_ECHO_REQUEST) {
			LOG_DBG("PING echo request with APS ACK received");
			ping_reply_ctx->send_ack = 1;
		} else {
			LOG_DBG("PING echo request without APS ACK received");
			ping_reply_ctx->send_ack = 0;
		}

		if (remote_node_addr.addr_type == ZB_ZCL_ADDR_TYPE_SHORT) {
			ping_reply_ctx->packet_info.dst_addr.addr_short =
				remote_node_addr.u.short_addr;
		} else {
			LOG_WRN("Drop ping request due to incorrect address type");
			ping_release_reply(ping_reply_ctx);
			zb_buf_free(bufid);
			return ZB_TRUE;
		}

		/* Send the Ping Reply, invalidate the row if not possible. */
		ping_reply_send(ping_reply_ctx);
	} else if (zcl_hdr->cmd_id == PING_NO_ECHO_REQUEST) {
		LOG_DBG("PING request without ECHO received");
	} else {
		LOG_WRN("Unsupported Ping message received, cmd_id %d",
			zcl_hdr->cmd_id);
	}

	zb_buf_free(bufid);
	return ZB_TRUE;
}

/** @brief ping over ZCL
 *
 * @code
 * zcl ping [--no-echo] [--aps-ack] <h:dst_addr> <d:payload size>
 * @endcode
 *
 * Example:
 * @code
 * zcl ping 0b010eaafd745dfa 32
 * @endcode
 *
 * @pre Ping only after starting @ref zigbee.
 *
 * Issue a ping-style command to another CLI device of the address `dst_addr`
 * by using `payload_size` bytes of payload.<br>
 *
 * Optionally, the device can request an APS acknowledgment (`--aps-ack`) or
 * ask destination not to sent ping reply (`--no-echo`).<br>
 *
 * To implement the ping-like functionality, a new custom cluster has been
 * defined with ID 64. There are four custom commands defined inside it,
 * each with its own ID.
 *
 * See the following flow graphs for details.
 *
 * - <b>Case 1:</b> Ping with echo, without the APS ack (default mode):
 *   @code
 *       App 1          Node 1                 Node 2
 *         |  -- ping ->  |  -- ping request ->  |   (command ID: 0x02 - ping request without the APS acknowledgment)
 *         |              |    <- MAC ACK --     |
 *         |              | <- ping reply --     |   (command ID: 0x01 - ping reply)
 *         |              |    -- MAC ACK ->     |
 *         |  <- Done --  |                      |
 *   @endcode
 *
 *   In this default mode, the `ping` command measures the time needed
 *   for a Zigbee frame to travel between two nodes in the network
 *   (there and back again). The command uses a custom "overloaded" ZCL frame,
 *   which is constructed as a ZCL frame of the new custom ping
 *   ZCL cluster (ID 64).
 *
 * - <b>Case 2:</b> Ping with echo, with the APS acknowledgment:
 *     @code
 *       App 1          Node 1                 Node 2
 *         |  -- ping ->  |  -- ping request ->  |   (command ID: 0x00 - ping request with the APS acknowledgment)
 *         |              |    <- MAC ACK --     |
 *         |              |    <- APS ACK --     |
 *         |              |    -- MAC ACK ->     |
 *         |              | <- ping reply --     |   (command ID: 0x01 - ping reply)
 *         |              |    -- MAC ACK ->     |
 *         |              |    -- APS ACK ->     |
 *         |              |    <- MAC ACK --     |
 *         |  <- Done --  |                      |
 *     @endcode
 *
 * - <b>Case 3:</b> Ping without echo, with the APS acknowledgment:
 *     @code
 *       App 1          Node 1                 Node 2
 *         |  -- ping ->  |  -- ping request ->  |   (command ID: 0x03 - ping request without echo)
 *         |              |    <- MAC ACK --     |
 *         |              |    <- APS ACK --     |
 *         |              |    -- MAC ACK ->     |
 *         |  <- Done --  |                      |
 *     @endcode
 *
 * - <b>Case 4:</b> Ping without echo, without the APS acknowledgment:
 *     @code
 *       App 1          Node 1                 Node 2
 *         |  -- ping ->  |  -- ping request ->  |   (command ID: 0x03 - ping request without echo)
 *         |  <- Done --  |                      |
 *         |              |    <- MAC ACK --     |
 *     @endcode
 */
int cmd_zb_ping(const struct shell *shell, size_t argc, char **argv)
{
	struct ping_request *ping_req_ctx;
	uint8_t i;

	ping_req_ctx = zb_ping_acquire_request();
	if (ping_req_ctx == NULL) {
		zb_cli_print_error(shell, "Request pool empty - wait a bit",
				   ZB_FALSE);
		return -ENOEXEC;
	}

	ping_req_ctx->cb = ping_cli_evt_handler;
	ping_req_ctx->request_ack = 0;
	ping_req_ctx->request_echo = 1;
	ping_req_ctx->timeout_ms = PING_ECHO_REQUEST_TIMEOUT_S * 1000;

	for (i = 1; i < (argc - 2); i++) {
		if (strcmp(argv[i], "--aps-ack") == 0) {
			ping_req_ctx->request_ack = 1;
		} else if (strcmp(argv[i], "--no-echo") == 0) {
			ping_req_ctx->request_echo = 0;
		}
	}

	ping_req_ctx->packet_info.dst_addr_mode =
		parse_address(argv[argc - 2],
			      &(ping_req_ctx->packet_info.dst_addr), ADDR_ANY);

	if (ping_req_ctx->packet_info.dst_addr_mode == ADDR_INVALID) {
		zb_cli_print_error(shell, "Wrong address format", ZB_FALSE);
		zb_ping_release_request(ping_req_ctx);
		return -EINVAL;
	}

	if (!zb_cli_sscan_uint(argv[argc - 1], (uint8_t *)&ping_req_ctx->count,
			       2, 10)) {

		zb_cli_print_error(shell, "Incorrect ping payload size",
				   ZB_FALSE);
		zb_ping_release_request(ping_req_ctx);
		return -EINVAL;
	}

	if (ping_req_ctx->count > PING_MAX_LENGTH) {
		shell_print(shell, "Note: Ping payload size exceeds maximum possible, assuming maximum");
		ping_req_ctx->count = PING_MAX_LENGTH;
	}

	/* Put the shell instance to be used later. */
	ping_req_ctx->shell = shell;

	ping_request_send(ping_req_ctx);
	return 0;
}
