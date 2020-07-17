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

LOG_MODULE_REGISTER(LOG_SUBMODULE_NAME, CONFIG_ZIGBEE_CLI_LOG_LEVEL);

/**@brief The row of the table which holds the replies which are to be sent.
 *
 * @details We use the table to temporarily store the parameters of the ping
 *          reply while it is traversing the ZBOSS callback system.
 *          The key parameter is the sequence number.
 */
typedef struct ping_reply_s {
	atomic_t            taken;
	zb_uint8_t          ping_seq;
	zb_uint8_t          count;
	zb_uint8_t          send_ack;
	const struct shell  *shell;
	zcl_packet_info_t   packet_info;
} ping_reply_t;


static ping_request_t m_ping_request_table[PING_TABLE_SIZE];
static ping_reply_t   m_ping_reply_table[PING_TABLE_SIZE];
static u8_t           m_ping_seq_num;
static ping_time_cb_t mp_ping_ind_cb = NULL;

static zb_uint32_t get_request_duration(ping_request_t *p_request);

ping_request_t *zb_ping_acquire_request(void)
{
	int i;
	for (i = 0; i < PING_TABLE_SIZE; i++) {
		if (atomic_get(&m_ping_request_table[i].taken) == ZB_FALSE) {
			atomic_set(&m_ping_request_table[i].taken, ZB_TRUE);
			return &(m_ping_request_table[i]);
		}
	}

	return NULL;
}

zb_void_t zb_ping_release_request(ping_request_t *p_reply)
{
	if (p_reply != NULL) {
		atomic_set(&p_reply->taken, ZB_FALSE);
		ZB_MEMSET(p_reply, 0x00, sizeof(ping_request_t));
	}
}

/**@brief Acquire ping reply context.
 *
 * @return  Pointer to a free ping reply context or NULL on failure.
 */
static ping_reply_t *ping_aquire_reply(void)
{
	int i;

	for (i = 0; i < PING_TABLE_SIZE; i++) {
		if (atomic_get(&m_ping_reply_table[i].taken) == ZB_FALSE) {
			atomic_set(&m_ping_reply_table[i].taken, ZB_TRUE);
			return &(m_ping_reply_table[i]);
		}
	}

	return NULL;
}

/**@brief Release ping reply context.
 *
 * @param p_reply Pointer to the reply context structure to release.
 */
zb_void_t ping_release_reply(ping_reply_t *p_reply)
{
	if (p_reply != NULL) {
		atomic_set(&p_reply->taken, ZB_FALSE);
		ZB_MEMSET(p_reply, 0x00, sizeof(ping_reply_t));
	}
}

/**@brief Invalidate Ping Request row after the timeout - ZBOSS callback
 *
 * @param row     Number of row to invalidate
 */
static zb_void_t invalidate_row_cb(zb_uint8_t row)
{
	ping_request_t *p_request = &(m_ping_request_table[row]);
	u32_t          delay_ms = get_request_duration(p_request);

	/* Inform user about timeout event. */
	if (p_request->p_cb) {
		p_request->p_cb(PING_EVT_FRAME_TIMEOUT, delay_ms, p_request);
	}

	zb_ping_release_request(p_request);
}

/**@brief Get the first row with request sent to addr_short.
 *
 * @param addr_short  Short network address to look for.
 *
 * @return  Pointer to the ping request context, NULL if none.
 */
static ping_request_t *find_request_by_short(zb_uint16_t addr_short)
{
	int i;
	zb_addr_u req_remote_addr;

	for (i = 0; i < PING_TABLE_SIZE; i++) {
		req_remote_addr = m_ping_request_table[i].packet_info.dst_addr;

		if (atomic_get(&m_ping_request_table[i].taken) == ZB_TRUE) {
			if (m_ping_request_table[i].packet_info.dst_addr_mode ==
			    ZB_APS_ADDR_MODE_16_ENDP_PRESENT) {
				if (req_remote_addr.addr_short == addr_short) {
					return &(m_ping_request_table[i]);
				}
			} else {
				if (zb_address_short_by_ieee(
					req_remote_addr.addr_long) ==
					 addr_short) {
					return &(m_ping_request_table[i]);
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
static ping_request_t *find_request_by_sn(zb_uint8_t seqnum)
{
	int i;

	for (i = 0; i < PING_TABLE_SIZE; i++) {
		if (atomic_get(&m_ping_request_table[i].taken) == ZB_TRUE) {
			if (m_ping_request_table[i].ping_seq == seqnum) {
				return &m_ping_request_table[i];
			}
		}
	}

	return NULL;
}

/**@brief Get row number for the ping request.
 *
 * @param[in] p_row Pointer to the ping request context.
 *
 * @return Row number, -1 if not found.
 */
static zb_int8_t get_request_row(ping_request_t *p_request)
{
	if (p_request != NULL) {
		return (p_request - m_ping_request_table);
	}

	return -1;
}

static void zb_zcl_send_ping_frame(zb_uint8_t idx, zb_uint16_t is_request)
{
	zb_ret_t zb_err_code;
	zcl_packet_info_t *packet_info;

	if (is_request) {
		packet_info = &(m_ping_request_table[idx].packet_info);

		/* Capture the sending time. */
		m_ping_request_table[idx].sent_time = k_uptime_ticks();
	} else {
		packet_info = &(m_ping_reply_table[idx].packet_info);
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
		ping_request_t *p_request = &m_ping_request_table[idx];

		if (zb_err_code != RET_OK) {
			print_error(p_request->shell,
				    "Can not send zcl frame", ZB_FALSE);
			zb_buf_free(packet_info->buffer);
			zb_ping_release_request(p_request);
			return;
		}

		zb_err_code = ZB_SCHEDULE_APP_ALARM(
					invalidate_row_cb,
					idx,
					ZB_MILLISECONDS_TO_BEACON_INTERVAL(
						p_request->timeout_ms));
		if (zb_err_code != RET_OK) {
			print_error(p_request->shell, "Can not schedule timeout alarm.",
				    ZB_FALSE);
			zb_ping_release_request(p_request);
			return;
		}

		if (p_request->p_cb) {
			u32_t time_diff = get_request_duration(p_request);
			p_request->p_cb(PING_EVT_FRAME_SCHEDULED, time_diff,
					p_request);
		}
	} else {
		if (zb_err_code != RET_OK) {
			print_error(m_ping_reply_table[idx].shell,
				    "Can not send zcl frame", ZB_FALSE);
			zb_buf_free(packet_info->buffer);
		}
		/* We don't need the row in this table anymore,
		 * since we're not expecting any reply to a Ping Reply.
		 */
		ping_release_reply(&(m_ping_reply_table[idx]));
	}
}

/**@brief Get time difference, in miliseconds between ping request identified
 *        by row number and current time.
 *
 * @param[in] p_row  Pointer to the ping request structure,
 *                   from which the time difference should be calculated.
 *
 * @return  Time difference in miliseconds.
 */
static zb_uint32_t get_request_duration(ping_request_t *p_request)
{
	u32_t time_diff_ms;
	s32_t time_diff_ticks;

	/* Calculate the time difference between request being sent
	 * and reply being received.
	 */
	time_diff_ticks = k_uptime_ticks() - p_request->sent_time;
	time_diff_ms = k_ticks_to_ms_near32(time_diff_ticks);

	return time_diff_ms;
}

static zb_void_t frame_acked_cb(zb_bufid_t bufid)
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
static zb_void_t dispatch_user_callback(zb_bufid_t bufid)
{
	zb_uint16_t                    short_addr;
	zb_zcl_command_send_status_t   *p_cmd_ping_status;
	zb_ret_t                       zb_err_code = RET_OK;
	ping_request_t                 *p_request = NULL;

	if (bufid == 0) {
		return;
	}

	p_cmd_ping_status = ZB_BUF_GET_PARAM(bufid,
					     zb_zcl_command_send_status_t);

	if (p_cmd_ping_status->dst_addr.addr_type == ZB_ZCL_ADDR_TYPE_SHORT) {
		short_addr = p_cmd_ping_status->dst_addr.u.short_addr;
	} else if (p_cmd_ping_status->dst_addr.addr_type ==
		   ZB_ZCL_ADDR_TYPE_IEEE) {
		short_addr = zb_address_short_by_ieee(
				p_cmd_ping_status->dst_addr.u.ieee_addr);
	} else {
		LOG_ERR("Ping request acknowledged with an unknown destination address type: %d",
			p_cmd_ping_status->dst_addr.addr_type);
		zb_buf_free(bufid);
		return;
	}

	p_request = find_request_by_short(short_addr);

	if (p_request != NULL) {
		u32_t delay_ms = get_request_duration(p_request);

		if (p_cmd_ping_status->status == RET_OK) {
			/* Inform user about ACK reception. */
			if (p_request->p_cb) {
				if (p_request->request_ack == 0) {
					p_request->p_cb(PING_EVT_FRAME_SENT,
							delay_ms, p_request);
				}
				else {
					p_request->p_cb(PING_EVT_ACK_RECEIVED,
							delay_ms, p_request);
				}
			}

			/* If only ACK was requested, cancel ongoing alarm. */
			if (p_request->request_echo == 0) {
				zb_err_code = ZB_SCHEDULE_APP_ALARM_CANCEL(
						invalidate_row_cb,
						get_request_row(p_request));
				if (zb_err_code == RET_OK) {
					zb_ping_release_request(p_request);
				}
			}
		} else {
			LOG_ERR("Ping request returned error status: %d",
				p_cmd_ping_status->status);
		}
	} else {
		LOG_WRN("Unknown ping command callback called with status: %d",
			p_cmd_ping_status->status);
	}

	zb_buf_free(bufid);
}

/**@brief  Default ping event handler. Prints out measured time on the CLI
 *         and exits.
 *
 * @param[in] evt_type  Type of received  ping acknowledgment
 * @param[in] delay_ms  Time, in miliseconds, between ping request
 *                      and the event.
 * @param[in] p_request Pointer to the ongoing ping request context structure.
 */
static void ping_cli_evt_handler(ping_time_evt_t evt, zb_uint32_t delay_ms,
				 ping_request_t *p_request)
{
	switch (evt) {
	case PING_EVT_FRAME_SCHEDULED:
		break;

	case PING_EVT_FRAME_TIMEOUT:
		shell_error(p_request->shell, "Error: Request timed out after %ld ms.",
			    delay_ms);
		break;

	case PING_EVT_ECHO_RECEIVED:
		shell_print(p_request->shell, "Ping time: %ld ms", delay_ms);
		print_done(p_request->shell, ZB_FALSE);
		break;

	case PING_EVT_ACK_RECEIVED:
		if (p_request->request_echo == 0) {
			shell_print(p_request->shell, "Ping time: %ld ms",
				    delay_ms);
			print_done(p_request->shell, ZB_FALSE);
		}
		break;

	case PING_EVT_FRAME_SENT:
		if ((p_request->request_echo == 0) &&
		    (p_request->request_ack  == 0)) {
			print_done(p_request->shell, ZB_FALSE);
		}
		break;

	case PING_EVT_ERROR:
		print_error(p_request->shell, "Unable to send ping request",
			    ZB_FALSE);
		break;

	default:
		LOG_ERR("Unknown ping event received: %d", evt);
		break;
	}
}

void zb_ping_set_ping_indication_cb(ping_time_cb_t p_cb)
{
	mp_ping_ind_cb = p_cb;
}

zb_void_t ping_request_send(ping_request_t *p_request)
{
	zb_uint8_t   cli_ep = zb_get_cli_endpoint();
	zb_ret_t     zb_err_code;
	zb_bufid_t   bufid;
	zb_uint8_t   *p_cmd_buf;

	if (p_request->count > PING_MAX_LENGTH) {
		if (p_request->p_cb) {
			p_request->p_cb(PING_EVT_ERROR, 0, p_request);
		}

		return;
	}

	bufid = zb_buf_get_out();
	if (!bufid) {
		if (p_request->p_cb) {
			p_request->p_cb(PING_EVT_ERROR, 0, p_request);
		}
		return;
	}

	/* Ping Frame is constructed by 'overloading' the common ZCL frame.
	 * Basically every frame which comes addressed
	 * to the PING_CUSTOM_CLUSTER is considered a Ping Frame. The FCF
	 * is being set to 0x00, the sequence number field is being used
	 * as a Ping Sequence Number, while the Command field
	 * is used to distinguish request/reply. The farther payload of the ping
	 * is filled with bytes PING_ECHO_REQUEST_BYTE/PING_ECHO_REPLY_BYTE.
	 */
	p_cmd_buf = ZB_ZCL_START_PACKET(bufid);
	*(p_cmd_buf++) = ZIGBEE_PING_FRAME_CONTROL_FIELD;
	/* Sequence Number Field. */
	*(p_cmd_buf++) = m_ping_seq_num;

	/* Fill Command Field. */
	if ((p_request->request_echo) && (p_request->request_ack)) {
		*(p_cmd_buf++) = PING_ECHO_REQUEST;
	} else if ((p_request->request_echo) && (!p_request->request_ack)) {
		*(p_cmd_buf++) = PING_ECHO_NO_ACK_REQUEST;
	} else {
		*(p_cmd_buf++) = PING_NO_ECHO_REQUEST;
	}

	memset(p_cmd_buf, PING_ECHO_REQUEST_BYTE, p_request->count);
	p_cmd_buf += p_request->count;
	p_request->ping_seq = m_ping_seq_num;
	m_ping_seq_num++;

	/* Schedle frame to send. */
	p_request->packet_info.buffer = bufid;
	p_request->packet_info.ptr = p_cmd_buf;
	/* DstAddr and Addr mode already set. */
	p_request->packet_info.dst_ep = cli_ep;
	p_request->packet_info.ep = cli_ep;
	p_request->packet_info.prof_id = ZB_AF_HA_PROFILE_ID;
	p_request->packet_info.cluster_id = PING_CUSTOM_CLUSTER;
	p_request->packet_info.cb = dispatch_user_callback;
	p_request->packet_info.disable_aps_ack =
		(p_request->request_ack ? ZB_FALSE : ZB_TRUE);

	zb_err_code = ZB_SCHEDULE_APP_CALLBACK2(zb_zcl_send_ping_frame,
						get_request_row(p_request),
						ZB_TRUE);
	if (zb_err_code != RET_OK) {
		print_error(p_request->shell,
				"Can not schedule zcl frame.",
				ZB_FALSE);
		zb_buf_free(p_request->packet_info.buffer);
		zb_ping_release_request(p_request);
		return;
	}
}

/**@brief Actually construct the Ping Reply frame and send it.
 *
 * @param p_row  Pointer to the ping reply context structure.
 */
static zb_void_t ping_reply_send(ping_reply_t *p_reply)
{
	zb_bufid_t   bufid;
	zb_uint8_t   *p_cmd_buf;
	zb_uint8_t   cli_ep = zb_get_cli_endpoint();
	zb_ret_t     zb_err_code;

	bufid = zb_buf_get_out();
	if (!bufid) {
		LOG_WRN("Drop ping request due to the lack of output buffers");
		ping_release_reply(p_reply);
		return;
	}
	LOG_DBG("Send ping reply");

	p_cmd_buf = ZB_ZCL_START_PACKET(bufid);
	*(p_cmd_buf++) = ZIGBEE_PING_FRAME_CONTROL_FIELD;
	*(p_cmd_buf++) = p_reply->ping_seq;
	*(p_cmd_buf++) = PING_ECHO_REPLY;
	memset(p_cmd_buf, PING_ECHO_REPLY_BYTE, p_reply->count);
	p_cmd_buf += p_reply->count;

	/* Schedule frame to send. */
	p_reply->packet_info.buffer = bufid;
	p_reply->packet_info.ptr = p_cmd_buf;
	/* DstAddr is already set. */
	p_reply->packet_info.dst_addr_mode = ZB_APS_ADDR_MODE_16_ENDP_PRESENT;
	p_reply->packet_info.dst_ep = cli_ep;
	p_reply->packet_info.ep = cli_ep;
	p_reply->packet_info.prof_id = ZB_AF_HA_PROFILE_ID;
	p_reply->packet_info.cluster_id = PING_CUSTOM_CLUSTER;
	p_reply->packet_info.cb = frame_acked_cb;
	p_reply->packet_info.disable_aps_ack =
		(p_reply->send_ack ? ZB_FALSE : ZB_TRUE);

	zb_err_code = ZB_SCHEDULE_APP_CALLBACK2(zb_zcl_send_ping_frame,
						(p_reply -
						 m_ping_reply_table),
						ZB_FALSE);
	if (zb_err_code != RET_OK) {
		print_error(p_reply->shell,
				"Can not schedule zcl frame.",
				ZB_FALSE);
		zb_buf_free(p_reply->packet_info.buffer);
		ping_release_reply(p_reply);
	}
}

/**@brief Indicate ping request reception.
 *
 * @param zcl_cmd_bufid  Zigbee buffer id with the received ZCL packet.
 */
static void ping_req_indicate(zb_bufid_t zcl_cmd_bufid)
{
	ping_request_t      tmp_request;
	zb_zcl_addr_t       remote_node_addr;
	zb_zcl_parsed_hdr_t *p_cmd_info = ZB_BUF_GET_PARAM(zcl_cmd_bufid,
							   zb_zcl_parsed_hdr_t);

	remote_node_addr = p_cmd_info->addr_data.common_data.source;

	if (mp_ping_ind_cb == NULL) {
		return;
	}

	memset(&tmp_request, 0, sizeof(ping_request_t));

	switch (p_cmd_info->cmd_id) {
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

	atomic_set(&tmp_request.taken, ZB_TRUE);
	tmp_request.ping_seq  = p_cmd_info->seq_number;
	tmp_request.count     = zb_buf_len(zcl_cmd_bufid);
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

	mp_ping_ind_cb(
		PING_EVT_REQUEST_RECEIVED,
		k_ticks_to_us_near32(tmp_request.sent_time),
		&tmp_request);
}

/**@brief The Handler to 'intercept' every frame coming to the endpoint.
 *
 * @param bufid    Reference to a ZBOSS buffer
 */
static zb_uint8_t cli_agent_ep_handler_ping(zb_bufid_t bufid)
{
	zb_zcl_addr_t       remote_node_addr;
	zb_zcl_parsed_hdr_t *p_cmd_info = ZB_BUF_GET_PARAM(bufid,
							   zb_zcl_parsed_hdr_t);
	zb_uint32_t time_diff;

	remote_node_addr = p_cmd_info->addr_data.common_data.source;

	if ((p_cmd_info->cluster_id != PING_CUSTOM_CLUSTER) ||
	    (p_cmd_info->profile_id != ZB_AF_HA_PROFILE_ID)) {
		return ZB_FALSE;
	}

	LOG_DBG("New ping frame received, bufid: %d", bufid);
	ping_req_indicate(bufid);

	if (p_cmd_info->cmd_id == PING_ECHO_REPLY) {
		zb_uint16_t remote_short_addr = 0x0000;

		/* We have our ping reply. */
		ping_request_t *p_request = find_request_by_sn(
						p_cmd_info->seq_number);
		if (p_request == NULL) {
			return ZB_FALSE;
		}

		if (p_request->packet_info.dst_addr_mode ==
		    ZB_APS_ADDR_MODE_16_ENDP_PRESENT) {
			remote_short_addr =
				p_request->packet_info.dst_addr.addr_short;
		} else {
			remote_short_addr = zb_address_short_by_ieee(
				p_request->packet_info.dst_addr.addr_long);
		}


		if (remote_node_addr.addr_type != ZB_ZCL_ADDR_TYPE_SHORT) {
			return ZB_FALSE;
		}
		if (remote_short_addr != remote_node_addr.u.short_addr) {
			return ZB_FALSE;
		}

		/* Catch the timer value. */
		time_diff = get_request_duration(p_request);

		/* Cancel the ongoing alarm which was to erase the row ... */
		zb_ret_t zb_err_code = ZB_SCHEDULE_APP_ALARM_CANCEL(
						invalidate_row_cb,
						get_request_row(p_request));
		ZB_ERROR_CHECK(zb_err_code);

		/* Call callback function in order to indicate
		 * echo response reception.
		 */
		if (p_request->p_cb) {
			p_request->p_cb(PING_EVT_ECHO_RECEIVED, time_diff,
					p_request);
		}

		/* ... and erase it manually. */
		if (zb_err_code == RET_OK) {
			zb_ping_release_request(p_request);
		}

	} else if ((p_cmd_info->cmd_id == PING_ECHO_REQUEST) ||
		   (p_cmd_info->cmd_id == PING_ECHO_NO_ACK_REQUEST)) {

		zb_uint8_t    len = zb_buf_len(bufid);
		ping_reply_t *p_reply = ping_aquire_reply();

		if (p_reply == NULL) {
			LOG_WRN("Cannot obtain new row for incoming ping request");
			return ZB_FALSE;
		}

		/* Save the Ping Reply information in the table and schedule
		 * a sending function.
		 */
		p_reply->count = len;
		p_reply->ping_seq = p_cmd_info->seq_number;

		if (p_cmd_info->cmd_id == PING_ECHO_REQUEST) {
			LOG_DBG("PING echo request with APS ACK received");
			p_reply->send_ack = 1;
		} else {
			LOG_DBG("PING echo request without APS ACK received");
			p_reply->send_ack = 0;
		}

		if (remote_node_addr.addr_type == ZB_ZCL_ADDR_TYPE_SHORT) {
			p_reply->packet_info.dst_addr.addr_short =
				remote_node_addr.u.short_addr;
		} else {
			LOG_WRN("Drop ping request due to incorrect address type");
			ping_release_reply(p_reply);
			zb_buf_free(bufid);
			return ZB_TRUE;
		}

		/* Send the Ping Reply, invalidate the row if not possible. */
		ping_reply_send(p_reply);
	} else if (p_cmd_info->cmd_id == PING_NO_ECHO_REQUEST) {
		LOG_DBG("PING request without ECHO received");
	} else {
		LOG_WRN("Unsupported Ping message received, cmd_id %d",
			p_cmd_info->cmd_id);
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
	ping_request_t *p_row;
	u8_t           i;

	p_row = zb_ping_acquire_request();
	if (p_row == NULL) {
		print_error(shell, "Request pool empty - wait a bit", ZB_FALSE);
		return -ENOEXEC;
	}

	p_row->p_cb         = ping_cli_evt_handler;
	p_row->request_ack  = 0;
	p_row->request_echo = 1;
	p_row->timeout_ms   = PING_ECHO_REQUEST_TIMEOUT_S * 1000;

	for (i = 1; i < (argc - 2); i++) {
		if (strcmp(argv[i], "--aps-ack") == 0) {
			p_row->request_ack = 1;
		} else if (strcmp(argv[i], "--no-echo") == 0) {
			p_row->request_echo = 0;
		}
	}

	p_row->packet_info.dst_addr_mode = parse_address(
						argv[argc - 2],
						&(p_row->packet_info.dst_addr),
						ADDR_ANY);
	if (p_row->packet_info.dst_addr_mode == ADDR_INVALID) {
		print_error(shell, "Wrong address format", ZB_FALSE);
		zb_ping_release_request(p_row);
		return -EINVAL;
	}

	if (!sscan_uint(argv[argc - 1], (u8_t*)&p_row->count, 2, 10)) {
		print_error(shell, "Incorrect ping payload size", ZB_FALSE);
		zb_ping_release_request(p_row);
		return -EINVAL;
	}

	if (p_row->count > PING_MAX_LENGTH) {
		shell_print(shell, "Note: Ping payload size exceeds maximum possible, assuming maximum");
		p_row->count = PING_MAX_LENGTH;
	}

	/* Put the shell instance to be used later. */
	p_row->shell = (const struct shell*)shell;

	ping_request_send(p_row);
	return 0;
}


/**@brief Endpoint handlers
 */
#ifndef DEVELOPMENT_TODO
#error "Endpoint handler register problem!"
NRF_ZIGBEE_EP_HANDLER_REGISTER(ping, cli_agent_ep_handler_ping);
#endif
