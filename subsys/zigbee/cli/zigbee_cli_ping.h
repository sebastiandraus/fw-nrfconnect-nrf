/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZIGBEE_CLI_PIN_H__
#define ZIGBEE_CLI_PIN_H__

#include <shell/shell.h>

#include <zboss_api.h>
#include <zboss_api_addons.h>

#define PING_CUSTOM_CLUSTER           0xBEEF
#define PING_MAX_LENGTH               79
#define PING_ECHO_REQUEST             0x00
#define PING_ECHO_REPLY               0x01
#define PING_ECHO_NO_ACK_REQUEST      0x02
#define PING_NO_ECHO_REQUEST          0x03
#define PING_ECHO_REQUEST_BYTE        0xAB
#define PING_ECHO_REPLY_BYTE          0xCD
#define PING_ECHO_REQUEST_TIMEOUT_S   10
#define PING_TABLE_SIZE               10

/**@brief  Ping event type. Informs what kind of acknowledgment was received.
 */
typedef enum {
	/* APS acknowledgement of PING request received. */
	PING_EVT_ACK_RECEIVED,
	/* PING reply received. */
	PING_EVT_ECHO_RECEIVED,
	/* PING reply or APS acknowledgment was not received
	 * within timeout time.
	 */
	PING_EVT_FRAME_TIMEOUT,
	/* PING request was successfully scheduled for sending by the stack. */
	PING_EVT_FRAME_SCHEDULED,
	/* PING request was successfully sent. This event occurrs only
	 * if both APS ACK was not requested.
	 */
	PING_EVT_FRAME_SENT,
	/* PING received was received. This event is passed only
	 * to the callback registered via @p zb_ping_set_ping_indication_cb. */
	PING_EVT_REQUEST_RECEIVED,
	/* An error occured during sending PING request. */
	PING_EVT_ERROR,
} ping_time_evt_t;

/**@brief Forward declaration of ping request context structure. */
typedef struct ping_request_s ping_request_t;

/**@brief  Ping event callback definition.
 *
 * @param[in] evt_type  Type of received  ping acknowledgment
 * @param[in] delay_us  Time, in microseconds, between ping request
 *                      and the event.
 * @param[in] p_row     Pointer to the ping request structure.
 */
typedef void (*ping_time_cb_t)(ping_time_evt_t evt, zb_uint32_t delay_us,
	      ping_request_t * p_request);

/**@brief The structure holds the BI interval value of ZBOSS timer
 *        and the value of the underlying 1MHz timer. Both combined give us the
 *        reliable way of measuring the time passed.
 */
typedef struct time_abs_s {
	zb_time_t   time_zb;
	zb_uint32_t time_tim;
} time_abs_t;

/**@brief The row of the table which holds the requests which were sent.
 *
 * @details We compare the incoming responses with the rows contents
 *          to determine if it is the answer.
 *          The key parameter is the sequence number.
 */
struct ping_request_s {
	zb_bool_t             taken;
	zb_addr_u             remote_addr;
	zb_uint8_t            remote_addr_mode;
	zb_uint8_t            ping_seq;
	zb_uint8_t            request_ack;
	zb_uint8_t            request_echo;
	zb_uint16_t           count;
	zb_uint16_t           timeout_ms;
	volatile time_abs_t   sent;
	const struct shell    *shell;
	ping_time_cb_t        p_cb;
};

/**@brief Set ping request indication callback.
 *
 * @note The @p p_cb argument delay_us will reflect current time
 *       in microseconds.
 */
void zb_ping_set_ping_indication_cb(ping_time_cb_t p_cb);

/**@brief Acquire ping request context.
 *
 * @return  Pointer to a free ping request context or NULL on failure.
 */
ping_request_t * zb_ping_acquire_request(void);

/**@brief Release ping request context.
 *
 * @param p_request Pointer to the context structure to release.
 */
zb_void_t zb_ping_release_request(ping_request_t * p_request);

/**@brief Actually construct the Ping Request frame and send it.
 *
 * @param p_request  Pointer to the ping request context structure.
 */
zb_void_t ping_request_send(ping_request_t * p_request);

#endif /* ZIGBEE_CLI_PIN_H__ */
