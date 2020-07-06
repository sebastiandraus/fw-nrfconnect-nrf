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
#include "zb_error_handler.h"

/** @brief ZCL Frame control field of Zigbee PING commands.
 */
#define ZIGBEE_PING_FRAME_CONTROL_FIELD 0x11

#ifndef DEVELOPMENT_TODO
#error "NRF LOG problem here"
// #if NRF_LOG_ENABLED
/** @brief Name of the submodule used for logger messaging.
 */
#define NRF_LOG_SUBMODULE_NAME ping

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
// #endif // NRF_LOG_ENABLED
#endif

LOG_MODULE_DECLARE(cli);

/**@brief The row of the table which holds the replies which are to be sent.
 *
 * @details We use the table to temporarily store the parameters of the ping reply
 *          while it is traversing the ZBOSS callback system.
 *          The key parameter is the sequence number.
 */
typedef struct ping_reply_s {
	zb_bool_t           taken;
	zb_uint16_t         remote_short_addr;
	zb_uint8_t          ping_seq;
	zb_uint8_t          count;
	zb_uint8_t          send_ack;
	const struct shell  *shell;
} ping_reply_t;


static ping_request_t m_ping_request_table[PING_TABLE_SIZE];
static ping_reply_t   m_ping_reply_table[PING_TABLE_SIZE];
static u8_t           m_ping_seq_num;
static ping_time_cb_t mp_ping_ind_cb = NULL;

#ifndef DEVELOPMENT_TODO
#error "NRF LOG Problem here"
// #if NRF_LOG_ENABLED
/* Logger instance used by this module. */
static log_ctx_t m_log = {
	NRF_LOG_INSTANCE_PTR_INIT(p_log, ZIGBEE_CLI_LOG_NAME, NRF_LOG_SUBMODULE_NAME)
};
// #endif // NRF_LOG_ENABLED
#endif

static zb_uint32_t get_request_duration(ping_request_t * p_request);

ping_request_t * zb_ping_acquire_request(void)
{
	int i;

	for (i = 0; i < PING_TABLE_SIZE; i++) {
		if (m_ping_request_table[i].taken == ZB_FALSE) {
			m_ping_request_table[i].taken = ZB_TRUE;
			return &(m_ping_request_table[i]);
		}
	}

	return NULL;
}

zb_void_t zb_ping_release_request(ping_request_t * p_reply)
{
	if (p_reply != NULL) {
		ZB_MEMSET(p_reply, 0x00, sizeof(ping_request_t));
	}
}

/**@brief Acquire ping reply context.
 *
 * @return  Pointer to a free ping reply context or NULL on failure.
 */
static ping_reply_t * ping_aquire_reply(void)
{
	int i;

	for (i = 0; i < PING_TABLE_SIZE; i++) {
		if (m_ping_reply_table[i].taken == ZB_FALSE) {
			m_ping_reply_table[i].taken = ZB_TRUE;
			return &(m_ping_reply_table[i]);
		}
	}

	return NULL;
}

/**@brief Release ping reply context.
 *
 * @param p_reply Pointer to the reply context structure to release.
 */
zb_void_t ping_release_reply(ping_reply_t * p_reply)
{
	if (p_reply != NULL) {
		ZB_MEMSET(p_reply, 0x00, sizeof(ping_reply_t));
	}
}

/**@brief Invalidate Ping Request row after the timeout - ZBOSS callback
 *
 * @param row     Number of row to invalidate
 */
static zb_void_t invalidate_row_cb(zb_uint8_t row)
{
	ping_request_t * p_request = &(m_ping_request_table[row]);
	u32_t            delay_us = get_request_duration(p_request);

	/* Inform user about timeout event. */
	if (p_request->p_cb) {
		p_request->p_cb(PING_EVT_FRAME_TIMEOUT, delay_us, p_request);
	}

	zb_ping_release_request(p_request);
}

/**@brief Get the first row with request sent to addr_short.
 *
 * @param addr_short  Short network address to look for.
 *
 * @return  Pointer to the ping request context, NULL if none.
 */
static ping_request_t * find_request_by_short(zb_uint16_t addr_short)
{
	int i;
	zb_addr_u req_remote_addr;

	for (i = 0; i < PING_TABLE_SIZE; i++) {
		req_remote_addr = m_ping_request_table[i].remote_addr;

		if (m_ping_request_table[i].taken == ZB_TRUE) {
			if (m_ping_request_table[i].remote_addr_mode ==
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
static ping_request_t * find_request_by_sn(zb_uint8_t seqnum)
{
	int i;

	for (i = 0; i < PING_TABLE_SIZE; i++) {
		if (m_ping_request_table[i].taken == ZB_TRUE) {
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
static zb_int8_t get_request_row(ping_request_t * p_request)
{
	if (p_request != NULL) {
		return (p_request - m_ping_request_table);
	}

	return -1;
}

/**@brief Get current abs time.
 */
static time_abs_t abs_time_now(void)
{
	time_abs_t now;
	now.time_zb = ZB_TIMER_GET();
#ifndef DEVELOPMENT_TODO
#error "Reference to NRF TIMER - replace with Zephyr timer, but no zboss-used timer!"
	/* Zigbee stack in end device role may disable timer at any time. */
#ifdef ZB_ED_ROLE
	now.time_tim = 0;
#else
	now.time_tim = nrf_drv_timer_capture(zb_nrf_cfg_get_zboss_timer(), NRF_TIMER_CC_CHANNEL2);
#endif
#endif
	return now;
}

/**@brief Get time difference, in microseconds between ping request identified
 *        by row number and current time.
 *
 * @param[in] p_row  Pointer to the ping request structure,
 *                   from which the time difference should be calculated.
 *
 * @return  Time difference in microseconds.
 */
static zb_uint32_t get_request_duration(ping_request_t * p_request)
{
	u32_t time_diff;

	/* Calculate the time difference between request being sent
	 * and reply being received.
	 */

#ifndef DEVELOPMENT_TODO
#error "NRF Timer reference here! We need to use Zephyr time based timer!"
	/* Zigbee stack in end device role may disable timer at any time. */
#ifdef ZB_ED_ROLE
	zb_uint32_t recv_tim = 0;
#else
	zb_uint32_t recv_tim = nrf_drv_timer_capture(zb_nrf_cfg_get_zboss_timer(), NRF_TIMER_CC_CHANNEL2);
#endif
	zb_time_t   recv_zb  = ZB_TIMER_GET();
	zb_uint32_t sent_tim = p_request->sent.time_tim;
	zb_time_t   sent_zb  = p_request->sent.time_zb;
	time_diff = (ZB_TIME_BEACON_INTERVAL_TO_USEC(ZB_TIME_SUBTRACT(recv_zb, sent_zb)) +
				 recv_tim) - sent_tim;
#endif

	return time_diff;
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
	zb_zcl_command_send_status_t * p_cmd_ping_status;
	zb_ret_t                       zb_err_code = RET_OK;
	ping_request_t               * p_request = NULL;

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
#ifndef DEVELOPMENT_TODO
#error "NRF LOG AGAIN"
		NRF_LOG_INST_ERROR(m_log.p_log, "Ping request acknowledged with an unknown destination address type: %d", p_cmd_ping_status->dst_addr.addr_type);
#endif
		zb_buf_free(bufid);
		return;
	}

	p_request = find_request_by_short(short_addr);

	if (p_request != NULL) {
		u32_t delay_us = get_request_duration(p_request);

		if (p_cmd_ping_status->status == RET_OK) {
			/* Inform user about ACK reception. */
			if (p_request->p_cb) {
				if (p_request->request_ack == 0) {
					p_request->p_cb(PING_EVT_FRAME_SENT,
							delay_us, p_request);
				}
				else {
					p_request->p_cb(PING_EVT_ACK_RECEIVED,
							delay_us, p_request);
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
#ifndef DEVELOPMENT_TODO
#error "NRF LOG problem here"
			NRF_LOG_INST_ERROR(m_log.p_log, "Ping request returned error status: %d", p_cmd_ping_status->status);
#endif
		}
	} else {
#ifndef DEVELOPMENT_TODO
#error "NRF LOG problem here"
		NRF_LOG_INST_WARNING(m_log.p_log, "Unknown ping command callback called with status: %d", p_cmd_ping_status->status);
#endif
	}

	zb_buf_free(bufid);
}

/**@brief  Default ping event handler. Prints out measured time on the CLI
 *         and exits.
 *
 * @param[in] evt_type  Type of received  ping acknowledgment
 * @param[in] delay_us  Time, in microseconds, between ping request
 *                      and the event.
 * @param[in] p_request Pointer to the ongoing ping request context structure.
 */
static void ping_cli_evt_handler(ping_time_evt_t evt, zb_uint32_t delay_us,
				 ping_request_t * p_request)
{
	switch (evt) {
	case PING_EVT_FRAME_SCHEDULED:
		break;

	case PING_EVT_FRAME_TIMEOUT:
		shell_error(p_request->shell, "\r\nError: Request timed out after %ld ms.\r\n", delay_us/1000);
		break;

	case PING_EVT_ECHO_RECEIVED:
		shell_print(p_request->shell, "\r\nPing time: %ld ms\r\n", delay_us/1000);
		print_done(p_request->shell, ZB_FALSE);
		break;

	case PING_EVT_ACK_RECEIVED:
		if (p_request->request_echo == 0) {
			shell_print(p_request->shell, "\r\nPing time: %ld ms\r\n", delay_us/1000);
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
		print_error(p_request->shell, "Unable to send ping request", ZB_TRUE);
		break;

	default:
#ifndef DEVELOPMENT_TODO
#error "NRF LOG problem here"
		NRF_LOG_INST_ERROR(m_log.p_log, "Unknown ping event received: %d", evt);
#endif
		break;
	}
}

void zb_ping_set_ping_indication_cb(ping_time_cb_t p_cb)
{
	mp_ping_ind_cb = p_cb;
}

zb_void_t ping_request_send(ping_request_t * p_request)
{
	zb_uint8_t   cli_ep = zb_get_cli_endpoint();
	zb_ret_t     zb_err_code;
	zb_bufid_t   bufid;
	zb_uint8_t * p_cmd_buf;

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

	/* Capture the sending time. */
	p_request->sent = abs_time_now();

	/* Actually send the frame. */
	if (p_request->request_ack) {
		zb_err_code = zb_zcl_finish_and_send_packet(
				bufid, p_cmd_buf, &(p_request->remote_addr),
				p_request->remote_addr_mode, cli_ep, cli_ep,
				ZB_AF_HA_PROFILE_ID, PING_CUSTOM_CLUSTER,
				dispatch_user_callback);
		ZB_ERROR_CHECK(zb_err_code);
	} else {
#ifndef DEVELOPMENT_TODO
#error "Lack of zb_zcl_finish_and_send_packet_no_ack, because of zb_zcl_common_addons.c & .h"
		zb_zcl_finish_and_send_packet_no_ack(
			bufid, p_cmd_buf, &(p_request->remote_addr),
			p_request->remote_addr_mode, cli_ep, cli_ep,
			ZB_AF_HA_PROFILE_ID, PING_CUSTOM_CLUSTER,
			dispatch_user_callback);
#endif
	}

	if (p_request->p_cb) {
		u32_t time_diff = get_request_duration(p_request);
		p_request->p_cb(PING_EVT_FRAME_SCHEDULED, time_diff, p_request);
	}

	zb_err_code = ZB_SCHEDULE_APP_ALARM(invalidate_row_cb,
					    get_request_row(p_request),
					    ZB_MILLISECONDS_TO_BEACON_INTERVAL(
						    p_request->timeout_ms));
	ZB_ERROR_CHECK(zb_err_code);
}

/**@brief Actually construct the Ping Reply frame and send it.
 *
 * @param p_row  Pointer to the ping reply context structure.
 */
static zb_void_t ping_reply_send(ping_reply_t * p_reply)
{
	zb_bufid_t   bufid;
	zb_uint8_t * p_cmd_buf;
	zb_uint8_t   cli_ep = zb_get_cli_endpoint();
	zb_ret_t     zb_err_code;

	bufid = zb_buf_get_out();
	if (!bufid) {
#ifndef DEVELOPMENT_TODO
#error "NRF LOG AGAIN"
		NRF_LOG_INST_WARNING(m_log.p_log, "Drop ping request due to the lack of output buffers");
#endif
		ping_release_reply(p_reply);
		return;
	}
#ifndef DEVELOPMENT_TODO
#error "NRF LOG AGAIN"
	NRF_LOG_INST_DEBUG(m_log.p_log, "Send ping reply");
#endif
	p_cmd_buf = ZB_ZCL_START_PACKET(bufid);
	*(p_cmd_buf++) = ZIGBEE_PING_FRAME_CONTROL_FIELD;
	*(p_cmd_buf++) = p_reply->ping_seq;
	*(p_cmd_buf++) = PING_ECHO_REPLY;
	memset(p_cmd_buf, PING_ECHO_REPLY_BYTE, p_reply->count);
	p_cmd_buf += p_reply->count;

	/* Actually send the frame */
	if (p_reply->send_ack) {
		zb_err_code = zb_zcl_finish_and_send_packet(
				bufid, p_cmd_buf,
				(zb_addr_u *)(&(p_reply->remote_short_addr)),
				ZB_APS_ADDR_MODE_16_ENDP_PRESENT, cli_ep,
				cli_ep, ZB_AF_HA_PROFILE_ID,
				PING_CUSTOM_CLUSTER, frame_acked_cb);
		ZB_ERROR_CHECK(zb_err_code);
	} else {
#ifndef DEVELOPMENT_TODO
#error "Lack of zb_zcl_finish_and_send_packet_no_ack, because of zb_zcl_common_addons.c & .h"
		zb_zcl_finish_and_send_packet_no_ack(
			bufid, p_cmd_buf,
			(zb_addr_u *)(&(p_reply->remote_short_addr)),
			ZB_APS_ADDR_MODE_16_ENDP_PRESENT, cli_ep, cli_ep,
			ZB_AF_HA_PROFILE_ID, PING_CUSTOM_CLUSTER,
			frame_acked_cb);
#endif
	}

	/* We don't need the row in this table anymore,
	 * since we're not expecting any reply to a Ping Reply.
	 */
	ping_release_reply(p_reply);
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

	tmp_request.taken    = ZB_TRUE;
	tmp_request.ping_seq = p_cmd_info->seq_number;
	tmp_request.count    = zb_buf_len(zcl_cmd_bufid);
	tmp_request.sent     = abs_time_now();

	if (remote_node_addr.addr_type != ZB_ZCL_ADDR_TYPE_SHORT) {
#ifndef DEVELOPMENT_TODO
#error "NRF LOG AGAIN"
		NRF_LOG_INFO("Ping request received, but indication will not be generated due to the unsupported address type.")
#endif
		/* Not supported. */
		return;
	}
	tmp_request.remote_addr_mode       = ZB_APS_ADDR_MODE_16_ENDP_PRESENT;
	tmp_request.remote_addr.addr_short = remote_node_addr.u.short_addr;

	mp_ping_ind_cb(
		PING_EVT_REQUEST_RECEIVED,
		ZB_TIME_BEACON_INTERVAL_TO_USEC(tmp_request.sent.time_zb),
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

#ifndef DEVELOPMENT_TODO
#error "NRF LOG here again"
	NRF_LOG_INST_DEBUG(m_log.p_log, "New ping frame received, bufid: %d", bufid);
#endif
	ping_req_indicate(bufid);

	if (p_cmd_info->cmd_id == PING_ECHO_REPLY) {
		zb_uint16_t remote_short_addr = 0x0000;

		/* We have our ping reply. */
		ping_request_t * p_request = find_request_by_sn(
						p_cmd_info->seq_number);
		if (p_request == NULL) {
			return ZB_FALSE;
		}

		if (p_request->remote_addr_mode ==
		    ZB_APS_ADDR_MODE_16_ENDP_PRESENT) {
			remote_short_addr = p_request->remote_addr.addr_short;
		} else {
			remote_short_addr = zb_address_short_by_ieee(
					      p_request->remote_addr.addr_long);
		}


		if (remote_node_addr.addr_type != ZB_ZCL_ADDR_TYPE_SHORT) {
			return ZB_FALSE;
		}
		if (remote_short_addr != remote_node_addr.u.short_addr) {
			return ZB_FALSE;
		}

		/* Catch the timers value. */
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

		zb_uint8_t     len = zb_buf_len(bufid);
		ping_reply_t * p_reply = ping_aquire_reply();

		if (p_reply == NULL) {
#ifndef DEVELOPMENT_TODO
#error "NRF LOG AGAIN!"
			NRF_LOG_INST_WARNING(m_log.p_log, "Cannot obtain new row for incoming ping request");
#endif
			return ZB_FALSE;
		}

		/* Save the Ping Reply information in the table and schedule
		 * a sending function.
		 */
		p_reply->count = len;
		p_reply->ping_seq = p_cmd_info->seq_number;

		if (p_cmd_info->cmd_id == PING_ECHO_REQUEST) {
#ifndef DEVELOPMENT_TODO
#error "NRF LOG AGAIN!"
			NRF_LOG_INST_DEBUG(m_log.p_log, "PING echo request with APS ACK received");
#endif
			p_reply->send_ack = 1;
		} else {
#ifndef DEVELOPMENT_TODO
#error "NRF LOG AGAIN!"
			NRF_LOG_INST_DEBUG(m_log.p_log, "PING echo request without APS ACK received");
#endif
			p_reply->send_ack = 0;
		}

		if (remote_node_addr.addr_type == ZB_ZCL_ADDR_TYPE_SHORT) {
			p_reply->remote_short_addr =
				remote_node_addr.u.short_addr;
		} else {
#ifndef DEVELOPMENT_TODO
#error "NRF LOG AGAIN!"
			NRF_LOG_INST_WARNING(m_log.p_log, "Drop ping request due to incorrect address type");
#endif
			ping_release_reply(p_reply);
			zb_buf_free(bufid);
			return ZB_TRUE;
		}

		/* Send the Ping Reply, invalidate the row if not possible. */
		ping_reply_send(p_reply);
	} else if (p_cmd_info->cmd_id == PING_NO_ECHO_REQUEST) {
#ifndef DEVELOPMENT_TODO
#error "NRF LOG AGAIN!"
		NRF_LOG_INST_DEBUG(m_log.p_log, "PING request without ECHO received");
#endif
	} else {
#ifndef DEVELOPMENT_TODO
#error "NRF LOG AGAIN!"
		NRF_LOG_INST_WARNING(m_log.p_log, "Unsupported Ping message received, cmd_id %d\r\n", p_cmd_info->cmd_id);
#endif
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
 * - <b>Case 1:</b> Ping with echo, without the APS acknowledgment (default mode):
 *   @code
 *       App 1          Node 1                 Node 2
 *         |  -- ping ->  |  -- ping request ->  |   (command ID: 0x02 - ping request without the APS acknowledgment)
 *         |              |    <- MAC ACK --     |
 *         |              | <- ping reply --     |   (command ID: 0x01 - ping reply)
 *         |              |    -- MAC ACK ->     |
 *         |  <- Done --  |                      |
 *   @endcode
 *
 *   In this default mode, the `ping` command measures the time needed for a Zigbee frame to travel between two nodes in the network (there and back again). The command uses a custom "overloaded" ZCL frame, which is constructed as a ZCL frame of the new custom ping ZCL cluster (ID 64).
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
	ping_request_t * p_row;
	u8_t          i;

#ifndef DEVELOPMENT_TODO
#error "NRF CLI help printer"
	if (nrf_cli_help_requested(p_cli) || (argc == 1)) {
		print_usage(p_cli, argv[0],
			    "[--no-echo] [--aps-ack] <h:addr> <d:payload size>");
		return -ENOEXEC;
	}
#endif
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

	p_row->remote_addr_mode = parse_address(argv[argc - 2],
						&(p_row->remote_addr),
						ADDR_ANY);
	if (p_row->remote_addr_mode == ADDR_INVALID) {
		print_error(shell, "Wrong address format", ZB_FALSE);
		zb_ping_release_request(p_row);
		return -EINVAL;
	}

	p_row->count = strtoul(argv[argc - 1], NULL, 10);
	if ((argv[argc - 1][0] < '0') || (argv[argc - 1][0] > '9') ||
	    (p_row->count > INT16_MAX)) {
		print_error(shell, "Incorrect ping payload size", ZB_FALSE);
		zb_ping_release_request(p_row);
		return -EINVAL;
	}

	if (p_row->count > PING_MAX_LENGTH) {
		shell_print(shell, "Note: Ping payload size exceeds maximum possible, assuming maximum\r\n");
		p_row->count = PING_MAX_LENGTH;
	}

	/* Put the CLI instance to be used later. */
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
