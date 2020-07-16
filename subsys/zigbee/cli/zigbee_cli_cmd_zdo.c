/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <string.h>
#include <shell/shell.h>

#include <zboss_api.h>
#include <zb_error_handler.h>
#include <zb_nrf_platform.h>
#include "zigbee_cli.h"
#include "zigbee_cli_utils.h"

#define BIND_ON_HELP \
	("Create bind entry.\n" \
	"Usage: on <h:source_eui64> <d:source_ep> <h:destination_addr> " \
		"<d:destination_ep> <h:source_cluster_id> <h:request_dst_addr>")

#define BIND_OFF_HELP \
	("Remove bind entry.\n" \
	"Usage: off <h:source_eui64> <d:source_ep> <h:destination_addr> " \
		"<d:destination_ep> <h:source_cluster_id> <h:request_dst_addr>")

#define ACTIVE_EP_HELP \
	("Send active endpoint request.\n" \
	"Usage: active_ep <h:16-bit destination_address>")

#define SIMPLE_DESC_HELP \
	("Send simple descriptor request.\n" \
	"Usage: simple_desc_req <h:16-bit destination_address> <d:endpoint>")

#define MATCH_DESC_HELP \
	("Send match descriptor request.\n" \
	"Usage: match_desc <h:16-bit destination_address> " \
		"<h:requested address/type> <h:profile ID> " \
		"<d:number of input clusters> [<h:input cluster IDs> ...] " \
		"<d:number of output clusters> [<h:output cluster IDs> ...] " \
		"[-t | --timeout d:number of seconds to wait for answers]")

#define NWK_ADDR_HELP \
	("Resolve EUI64 address to short network address.\n" \
	"Usage: nwk_addr <h:EUI64>")

#define IEEE_ADDR_HELP \
	("Resolve network short address to EUI64 address.\n" \
	"Usage: ieee_addr <h:short_addr>")

#define EUI64_HELP \
	("Get/set the eui64 address of the node.\n" \
	"Usage: eui64 [<h:eui64>]")

#define MGMT_BIND_HELP \
	("Get binding table (see spec. 2.4.3.3.4)\n" \
	"Usage: <h:short> [d:start_index]")

#define MGMT_LEAVE_HELP \
	("Perform mgmt_leave_req (see spec. 2.4.3.3.5)\n" \
	"Usage: mgmt_leave <h:16-bit dst_addr> [h:device_address eui64] " \
		"[--children] [--rejoin]\n" \
	"--children - Device should also remove its children when leaving.\n" \
	"--rejoin - Device should rejoin network after leave.")

#define MGMT_LQI_HELP \
	("Perform mgmt_lqi request.\n" \
	"Usage: mgmt_lqi <h:short> [d:start index]")

/* Defines how many ZDO requests can be run concurrently. */
#define ZIGBEE_CLI_ZDO_TSN                 3
/* Defines how long to wait, in seconds, for Match Descriptor Response. */
#define ZIGBEE_CLI_MATCH_DESC_RESP_TIMEOUT 5
/* Defines how long to wait, in seconds, for Bind Response. */
#define ZIGBEE_CLI_BIND_RESP_TIMEOUT       5
/* Defines how long to wait, in seconds, for Network Addrees Response. */
#define ZIGBEE_CLI_NWK_ADDR_RESP_TIMEOUT   5
/* Defines how long to wait, in seconds, for IEEE (EUI64) Addrees Response. */
#define ZIGBEE_CLI_IEEE_ADDR_RESP_TIMEOUT  5
/* Defines how long to wait, in seconds, for mgmt_leave response. */
#define ZIGBEE_CLI_MGMT_LEAVE_RESP_TIMEOUT 5


LOG_MODULE_DECLARE(cli);

typedef struct {
	/* Starting Index for the requested elements. */
	zb_uint8_t  start_index;
	/* Destination address. */
	zb_uint16_t dst_addr;
} req_seq_t;

/* Forward declarations. */
static void ctx_timeout_cb(zb_uint8_t tsn);

/* This structure allows for binding ZBOSS transaction and CLI object.. */
typedef struct zdo_tsn_ctx {
	const struct shell *shell;
	bool               (*p_cb_fn)(struct zdo_tsn_ctx *zdo_tsn_ctx, u8_t param);
	u8_t               tsn;
	bool               is_broadcast;
	atomic_t           taken;
	union {
		/* Extra context for commands which request tables. */
		req_seq_t req_seq;
	} cmd_ctx;
	zb_bufid_t         buffer_id;
	zb_uint8_t         ctx_timeout;
	void               (*p_zdo_timeout_cb_fn)(zb_bufid_t);
	zb_uint8_t         (*p_zdo_req_fn)(zb_uint8_t, zb_callback_t);
	void               (*p_zdo_request_cb_fn)(zb_bufid_t);
} zdo_tsn_ctx_t;

static zdo_tsn_ctx_t m_tsn_ctx[ZIGBEE_CLI_ZDO_TSN];

/**@brief Return a pointer to context with the given transaction
 *        sequence number.
 *
 * @param[in] tsn ZBOSS transaction sequence number.
 *
 * @return a pointer to context or NULL if context for given TSN wasn't found.
 */
static zdo_tsn_ctx_t * get_ctx_by_tsn(u8_t tsn)
{
	for (u8_t i = 0; i < ARRAY_SIZE(m_tsn_ctx); i++) {
		if ((atomic_get(&m_tsn_ctx[i].taken)) &&
		    (m_tsn_ctx[i].tsn == tsn)) {
			return &m_tsn_ctx[i];
		}
	}

	return NULL;
}

/**@brief Get a pointer to a free context.
 *
 * @return a pointer to context structure or NULL if all contexts are taken.
 */
static zdo_tsn_ctx_t *get_free_ctx(void)
{
	for (u8_t i = 0; i < ARRAY_SIZE(m_tsn_ctx); i++) {
		if (!atomic_get(&m_tsn_ctx[i].taken)) {
			atomic_set(&m_tsn_ctx[i].taken, true);

			return &m_tsn_ctx[i];
		}
	}

	return NULL;
}

/**@brief Invalidate context.
 *
 * @param[in] p_tsn_ctx a pointer to transaction context.
 */
static void invalidate_ctx(zdo_tsn_ctx_t *p_tsn_ctx)
{
	p_tsn_ctx->tsn                 = 0xFF;
	p_tsn_ctx->shell               = NULL;
	p_tsn_ctx->p_cb_fn             = NULL;
	p_tsn_ctx->is_broadcast        = false;
	p_tsn_ctx->buffer_id           = 0;
	p_tsn_ctx->ctx_timeout         = 0;
	p_tsn_ctx->p_zdo_req_fn        = NULL;
	p_tsn_ctx->p_zdo_request_cb_fn = NULL;
	atomic_set(&p_tsn_ctx->taken, false);
}

/**@brief Parse a list of cluster IDs.
 *
 * @param[in]  pp_argv Pointer to argument table.
 * @param[in]  num     Number of cluster IDs to scan.
 * @param[out] pp_id   Pointer to an array to store cluster IDs.
 *
 * @return 1 if parsing succeeded, 0 otherwise.
 *
 */
static int sscan_cluster_list(char ** pp_argv, u8_t num, u16_t * pp_id)
{
	u16_t len = 0;

	while ((len < num) && parse_hex_u16(pp_argv[len], pp_id)) {
		len += 1;
		pp_id += 1;
	}

	return (len == num);
}

static void zb_zdo_req(u8_t idx)
{
	zdo_tsn_ctx_t *p_tsn_cli = (m_tsn_ctx + idx);
	zb_ret_t      zb_err_code;

	/* Call the actual request function. */
	p_tsn_cli->tsn   = p_tsn_cli->p_zdo_req_fn(
				p_tsn_cli->buffer_id,
				p_tsn_cli->p_zdo_request_cb_fn);

	if (p_tsn_cli->tsn == ZB_ZDO_INVALID_TSN) {
		print_error(p_tsn_cli->shell, "Failed to send request",
			    ZB_FALSE);
		invalidate_ctx(p_tsn_cli);
		zb_buf_free(p_tsn_cli->buffer_id);
		return;

	} else if (p_tsn_cli->ctx_timeout && p_tsn_cli->p_zdo_timeout_cb_fn) {
		zb_err_code = ZB_SCHEDULE_APP_ALARM(
				p_tsn_cli->p_zdo_timeout_cb_fn,
				p_tsn_cli->tsn,
				p_tsn_cli->ctx_timeout * ZB_TIME_ONE_SECOND);
		if (zb_err_code != RET_OK) {
			print_error(p_tsn_cli->shell, "Unable to schedule timeout callback",
				    ZB_FALSE);
			invalidate_ctx(p_tsn_cli);
		}
	}
	return;
}

/**@brief Handles timeout error and invalidates match descriptor request transaction.
 *
 * @param[in] tsn ZBOSS transaction sequence number.
 */
static void cmd_zb_match_desc_timeout(zb_uint8_t tsn)
{
	zdo_tsn_ctx_t * p_tsn_ctx = get_ctx_by_tsn(tsn);

	if (!p_tsn_ctx) {
		return;
	}

	print_done(p_tsn_ctx->shell, ZB_FALSE);
	invalidate_ctx(p_tsn_ctx);
}

/**@brief A callback called on match descriptor response.
 *
 * @param[in] bufid Reference number to ZBOSS memory buffer.
 */
static void cmd_zb_match_desc_cb(zb_bufid_t bufid)
{
	zb_zdo_match_desc_resp_t   *p_resp;
	zb_apsde_data_indication_t *p_ind;
	zdo_tsn_ctx_t              *p_tsn_ctx;

	p_resp = (zb_zdo_match_desc_resp_t *)zb_buf_begin(bufid);
	p_ind  = ZB_BUF_GET_PARAM(bufid, zb_apsde_data_indication_t);
	p_tsn_ctx = get_ctx_by_tsn(p_resp->tsn);

	if (p_tsn_ctx) {
		if (p_resp->status == ZB_ZDP_STATUS_SUCCESS) {
			zb_uint8_t * p_match_ep = (zb_uint8_t *)(p_resp + 1);

			shell_print(p_tsn_ctx->shell, "");
			while (p_resp->match_len > 0) {
				/* Match EP list follows right after
				 * response header.
				 */
				shell_print(p_tsn_ctx->shell,
					    "src_addr=%0hx ep=%d",
					    p_ind->src_addr, *p_match_ep);

				p_match_ep += 1;
				p_resp->match_len -= 1;
			}

			if (!p_tsn_ctx->is_broadcast) {
				print_done(p_tsn_ctx->shell, ZB_FALSE);
				invalidate_ctx(p_tsn_ctx);
			}
		} else if (p_resp->status == ZB_ZDP_STATUS_TIMEOUT) {
			print_done(p_tsn_ctx->shell, ZB_FALSE);
			invalidate_ctx(p_tsn_ctx);
		}
	}

	zb_buf_free(bufid);
}

static zb_void_t cmd_zb_active_ep_cb(zb_bufid_t bufid)
{
	zb_zdo_ep_resp_t *p_resp = (zb_zdo_ep_resp_t *)zb_buf_begin(bufid);
	zdo_tsn_ctx_t    *p_tsn_ctx;

	p_tsn_ctx = get_ctx_by_tsn(p_resp->tsn);
	if (!p_tsn_ctx) {
		zb_buf_free(bufid);
		return;
	}

	if (p_resp->status == ZB_ZDP_STATUS_SUCCESS) {
		char text_buffer[150] = "";
		sprintf(text_buffer, "src_addr=%0hx ", p_resp->nwk_addr);

		PRINT_LIST(text_buffer, "ep=", "%d", zb_uint8_t,
			   (zb_uint8_t *)p_resp + sizeof(zb_zdo_ep_resp_t),
			   p_resp->ep_count);

		shell_print(p_tsn_ctx->shell, "%s", text_buffer);

		print_done(p_tsn_ctx->shell, ZB_FALSE);
	} else {
		print_error(p_tsn_ctx->shell, "Active ep request failed",
			    ZB_FALSE);
	}

	invalidate_ctx(p_tsn_ctx);
	zb_buf_free(bufid);
}

static zb_void_t cmd_zb_simple_desc_req_cb(zb_bufid_t bufid)
{
	zdo_tsn_ctx_t             *p_tsn_ctx;
	zb_zdo_simple_desc_resp_t *p_resp;
	zb_uint8_t                in_cluster_cnt;
	zb_uint8_t                out_cluster_cnt;
	zb_uint16_t               *p_cluster_list;

	p_resp = (zb_zdo_simple_desc_resp_t *)zb_buf_begin(bufid);
	in_cluster_cnt  = p_resp->simple_desc.app_input_cluster_count;
	out_cluster_cnt = p_resp->simple_desc.app_output_cluster_count;
	p_cluster_list  = (zb_uint16_t *)p_resp->simple_desc.app_cluster_list;

	p_tsn_ctx = get_ctx_by_tsn(p_resp->hdr.tsn);
	if (!p_tsn_ctx) {
		zb_buf_free(bufid);
		return;
	}

	if (p_resp->hdr.status == ZB_ZDP_STATUS_SUCCESS) {
		char text_buffer[150] = "";
		sprintf(text_buffer, "src_addr=0x%0hx ep=%d profile_id=0x%04hx app_dev_id=0x%0hx app_dev_ver=0x%0hx ",
			p_resp->hdr.nwk_addr, p_resp->simple_desc.endpoint,
			p_resp->simple_desc.app_profile_id,
			p_resp->simple_desc.app_device_id,
			p_resp->simple_desc.app_device_version);

		PRINT_LIST(text_buffer, "in_clusters=", "0x%04hx", zb_uint16_t,
			   p_cluster_list, in_cluster_cnt);

		PRINT_LIST(text_buffer, "out_clusters=", "0x%04hx", zb_uint16_t,
			   p_cluster_list + in_cluster_cnt,
			   out_cluster_cnt);

		shell_print(p_tsn_ctx->shell, "%s", text_buffer);

		print_done(p_tsn_ctx->shell, ZB_FALSE);
	} else {
		print_error(p_tsn_ctx->shell, "Active ep request failed",
			    ZB_FALSE);
	}

	invalidate_ctx(p_tsn_ctx);
	zb_buf_free(bufid);
}

/**@brief Handles timeout error and invalidates binding transaction.
 *
 * @param[in] tsn ZBOSS transaction sequence number.
 */
static void cmd_zb_bind_unbind_timeout(zb_uint8_t tsn)
{
	zdo_tsn_ctx_t *p_tsn_ctx = get_ctx_by_tsn(tsn);

	if (!p_tsn_ctx) {
		return;
	}

	print_error(p_tsn_ctx->shell, "Bind/unbind request timed out",
		    ZB_FALSE);
	invalidate_ctx(p_tsn_ctx);
}

/**@brief A callback called on bind/unbind response.
 *
 * @param[in] bufid Reference number to ZBOSS memory buffer.
 */
zb_void_t cmd_zb_bind_unbind_cb(zb_bufid_t bufid)
{
	zb_zdo_bind_resp_t * p_resp = (zb_zdo_bind_resp_t *)zb_buf_begin(bufid);
	zdo_tsn_ctx_t      * p_tsn_ctx;
	zb_ret_t             zb_err_code;

	p_tsn_ctx = get_ctx_by_tsn(p_resp->tsn);
	if (!p_tsn_ctx) {
		zb_buf_free(bufid);
		return;
	}

	zb_err_code = ZB_SCHEDULE_APP_ALARM_CANCEL(cmd_zb_bind_unbind_timeout,
						   ZB_ALARM_ANY_PARAM);
	if (zb_err_code != RET_OK) {
		print_error(p_tsn_ctx->shell, "Unable to cancel timeout timer",
			    ZB_FALSE);
	}

	if (p_resp->status == ZB_ZDP_STATUS_SUCCESS) {
		print_done(p_tsn_ctx->shell, ZB_FALSE);
	} else {
		shell_error(p_tsn_ctx->shell, "Error: Unable to modify binding. Status: %d",
			    p_resp->status);
	}

	invalidate_ctx(p_tsn_ctx);
	zb_buf_free(bufid);
}

/**@brief Handles timeout error and invalidates network address
 *        request transaction.
 *
 * @param[in] tsn ZBOSS transaction sequence number.
 */
static void cmd_zb_nwk_addr_timeout(zb_uint8_t tsn)
{
	zdo_tsn_ctx_t * p_tsn_ctx = get_ctx_by_tsn(tsn);

	if (!p_tsn_ctx) {
		return;
	}

	print_error(p_tsn_ctx->shell, "Network address request timed out",
		    ZB_FALSE);
	invalidate_ctx(p_tsn_ctx);
}

/**@brief A callback called on network address response.
 *
 * @param[in] bufid Reference number to ZBOSS memory buffer.
 */
zb_void_t cmd_zb_nwk_addr_cb(zb_bufid_t bufid)
{
	zb_zdo_nwk_addr_resp_head_t *p_resp;
	zdo_tsn_ctx_t               *p_tsn_ctx;
	zb_ret_t                     zb_err_code;

	p_resp = (zb_zdo_nwk_addr_resp_head_t *)zb_buf_begin(bufid);
	p_tsn_ctx = get_ctx_by_tsn(p_resp->tsn);
	if (!p_tsn_ctx) {
		zb_buf_free(bufid);
		return;
	}

	zb_err_code = ZB_SCHEDULE_APP_ALARM_CANCEL(cmd_zb_nwk_addr_timeout,
						   ZB_ALARM_ANY_PARAM);
	if (zb_err_code != RET_OK) {
		print_error(p_tsn_ctx->shell, "Unable to cancel timeout timer",
			    ZB_FALSE);
	}

	if (p_resp->status == ZB_ZDP_STATUS_SUCCESS) {
		zb_uint16_t nwk_addr;

		ZB_LETOH16(&nwk_addr, &(p_resp->nwk_addr));
		shell_print(p_tsn_ctx->shell, "%hx", nwk_addr);
		print_done(p_tsn_ctx->shell, ZB_FALSE);
	} else {
		shell_error(p_tsn_ctx->shell, "Error: Unable to resolve EUI64 source address. Status: %d",
			    p_resp->status);
	}

	invalidate_ctx(p_tsn_ctx);
	zb_buf_free(bufid);
}

/**@brief Handles timeout error and invalidates IEEE (EUI64) address
 *        request transaction.
 *
 * @param[in] tsn ZBOSS transaction sequence number.
 */
static void cmd_zb_ieee_addr_timeout(zb_uint8_t tsn)
{
	zdo_tsn_ctx_t * p_tsn_ctx = get_ctx_by_tsn(tsn);

	if (p_tsn_ctx) {
		print_error(p_tsn_ctx->shell, "IEEE address request timed out",
			    ZB_FALSE);
		invalidate_ctx(p_tsn_ctx);
	}
}

/**@brief A callback called on IEEE (EUI64) address response.
 *
 * @param[in] bufid Reference number to ZBOSS memory buffer.
 */
zb_void_t cmd_zb_ieee_addr_cb(zb_bufid_t bufid)
{
	zb_zdo_ieee_addr_resp_t *p_resp;
	zdo_tsn_ctx_t           *p_tsn_ctx;
	zb_ret_t                 zb_err_code;

	p_resp = (zb_zdo_ieee_addr_resp_t *)zb_buf_begin(bufid);
	p_tsn_ctx = get_ctx_by_tsn(p_resp->tsn);
	if (!p_tsn_ctx) {
		zb_buf_free(bufid);
		return;
	}

	zb_err_code = ZB_SCHEDULE_APP_ALARM_CANCEL(cmd_zb_ieee_addr_timeout,
						   ZB_ALARM_ANY_PARAM);
	if (zb_err_code != RET_OK) {
		print_error(p_tsn_ctx->shell, "Unable to cancel timeout timer",
			    ZB_FALSE);
	}

	if (p_resp->status == ZB_ZDP_STATUS_SUCCESS) {
		zb_address_ieee_ref_t addr_ref;
		zb_ieee_addr_t        ieee_addr;
		zb_uint16_t           nwk_addr;
		zb_ret_t              ret;

		ZB_LETOH64(ieee_addr, p_resp->ieee_addr_remote_dev);
		ZB_LETOH16(&nwk_addr, &(p_resp->nwk_addr_remote_dev));

		/* Update local IEEE address resolution table. */
		ret = zb_address_update(ieee_addr, nwk_addr, ZB_TRUE,
					&addr_ref);
		if (ret == RET_OK) {
			print_eui64(p_tsn_ctx->shell, ieee_addr);
			/* Prepend newline because `print_eui64`
			 * does not print LF.
			 */
			print_done(p_tsn_ctx->shell, ZB_TRUE);
		} else {
			shell_error(p_tsn_ctx->shell, "Error: Failed to updated address table. Status: %d",
				    ret);
		}
	} else {
		shell_error(p_tsn_ctx->shell, "Error: Unable to resolve IEEE address. Status: %d",
			    p_resp->status);
	}

	invalidate_ctx(p_tsn_ctx);
	zb_buf_free(bufid);
}

/**@brief Send Active Endpoint Request.
 *
 * @code
 * zdo active_ep <h:16-bit destination_address>
 * @endcode
 *
 * Send Active Endpoint Request to the node addressed by the short address.
 *
 * Example:
 * @code
 * > zdo active_ep 0xb4fc
 * > src_addr=B4FC ep=10,11,12
 * Done
 * @endcode
 *
 */
static int cmd_zb_active_ep(const struct shell *shell, size_t argc, char **argv)
{
	zb_zdo_active_ep_req_t    * p_req;
	zdo_tsn_ctx_t             * p_tsn_cli;
	zb_bufid_t                  bufid;
	u16_t                       addr;
	zb_ret_t                    zb_err_code;

	bufid = zb_buf_get_out();
	if (!bufid) {
		print_error(shell, "Failed to execute command (buf alloc failed)",
			    ZB_FALSE);
		return -ENOEXEC;
	}

	p_req = zb_buf_initial_alloc(bufid, sizeof(*p_req));

	if (!parse_hex_u16(argv[1], &addr)) {
		print_error(shell, "Incorrect network address", ZB_FALSE);
		goto error;
	}
	p_req->nwk_addr = addr;

	p_tsn_cli = get_free_ctx();
	if (!p_tsn_cli) {
		print_error(shell, "Too many ZDO transactions", ZB_FALSE);
		zb_buf_free(bufid);
		return -ENOEXEC;
	}

	/* Initialize context and send a request. */
	p_tsn_cli->shell = shell;
	p_tsn_cli->buffer_id = bufid;
	p_tsn_cli->p_zdo_req_fn = zb_zdo_active_ep_req;
	p_tsn_cli->p_zdo_request_cb_fn = cmd_zb_active_ep_cb;
	p_tsn_cli->ctx_timeout = 0;
	p_tsn_cli->p_zdo_timeout_cb_fn = NULL;

	zb_err_code = zigbee_schedule_callback(zb_zdo_req,
					       (p_tsn_cli - m_tsn_ctx));
	if (zb_err_code != RET_OK) {
		print_error(shell, "Unable to schedule zdo request", ZB_FALSE);
		invalidate_ctx(p_tsn_cli);
		zb_buf_free(bufid);
		return -ENOEXEC;
	}

	return 0;

error:
	zb_buf_free(bufid);
	return -EINVAL;
}

/**@brief Send Simple Descriptor Request.
 *
 * @code
 * zdo simple_desc_req <h:16-bit destination_address> <d:endpoint>
 * @endcode
 *
 * Send Simple Descriptor Request to the given node and endpoint.
 *
 * Example:
 * @code
 * > zdo simple_desc_req 0xefba 10
 * > src_addr=0xEFBA ep=260 profile_id=0x0102 app_dev_id=0x0 app_dev_ver=0x5
 *   in_clusters=0x0000,0x0003,0x0004,0x0005,0x0006,0x0008,0x0300
 *   out_clusters=0x0300
 * Done
 * @endcode
 *
 */
static int cmd_zb_simple_desc(const struct shell *shell, size_t argc,
			      char **argv)
{
	zb_zdo_simple_desc_req_t *p_req;
	zdo_tsn_ctx_t            *p_tsn_cli;
	zb_bufid_t                bufid;
	zb_uint16_t               addr;
	zb_ret_t                  zb_err_code;

	bufid = zb_buf_get_out();
	if (!bufid) {
		print_error(shell, "Failed to execute command (buf alloc failed)",
			    ZB_FALSE);
		return -ENOEXEC;
	}

	p_req = zb_buf_initial_alloc(bufid, sizeof(*p_req));

	if (!parse_hex_u16(argv[1], &addr)) {
		print_error(shell, "Invalid network address", ZB_FALSE);
		goto error;
	}
	p_req->nwk_addr = addr;

	if (!sscan_uint8(argv[2], &(p_req->endpoint))) {
		print_error(shell, "Invalid endpoint", ZB_FALSE);
		goto error;
	}

	p_tsn_cli = get_free_ctx();
	if (!p_tsn_cli) {
		print_error(shell, "Too many ZDO transactions", ZB_FALSE);
		zb_buf_free(bufid);
		return -ENOEXEC;
	}

	/* Initialize context and send a request. */
	p_tsn_cli->shell = shell;
	p_tsn_cli->buffer_id = bufid;
	p_tsn_cli->p_zdo_req_fn = zb_zdo_simple_desc_req;
	p_tsn_cli->p_zdo_request_cb_fn = cmd_zb_simple_desc_req_cb;
	p_tsn_cli->ctx_timeout = 0;
	p_tsn_cli->p_zdo_timeout_cb_fn = NULL;

	zb_err_code = zigbee_schedule_callback(zb_zdo_req,
					       (p_tsn_cli - m_tsn_ctx));
	if (zb_err_code != RET_OK) {
		print_error(shell, "Unable to schedule zdo request", ZB_FALSE);
		invalidate_ctx(p_tsn_cli);
		zb_buf_free(bufid);
		return -ENOEXEC;
	}

	return 0;

error:
	zb_buf_free(bufid);
	return -EINVAL;
}

/**@brief Send match descriptor request.
 *
 * @code
 * zdo match_desc <h:16-bit destination_address>
	<h:requested address/type> <h:profile ID>
	<d:number of input clusters> [<h:input cluster IDs> ...]
	<d:number of output clusters> [<h:output cluster IDs> ...]
	[-t | --timeout <n seconds>]
 *
 * @endcode
 *
 * Send Match Descriptor Request to the `dst_addr` node that is a
 * query about the `req_addr` node of the `prof_id` profile ID,
 * which must have at least one of `n_input_clusters`(whose IDs are listed
 * in `{...}`) or `n_output_clusters` (whose IDs are listed in `{...}`).
 * The IDs can be either decimal values or hexadecimal strings.
 * Set the timeout of request with `-t` of `--timeout` optional parameter.
 *
 * Example:
 * @code
 * zdo match_desc 0xfffd 0xfffd 0x0104 1 6 0
 * @endcode
 *
 * In this example, the command sends a Match Descriptor Request to all
 * non-sleeping nodes regarding all non-sleeping nodes that have
 * 1 input cluster ON/OFF (ID 6) and 0 output clusters.
 *
 */
static int cmd_zb_match_desc(const struct shell *shell, size_t argc,
			     char **argv)
{
	zb_zdo_match_desc_param_t *p_req;
	zdo_tsn_ctx_t             *p_tsn_cli;
	zb_bufid_t                 bufid;
	u16_t                     *p_cluster_list = NULL;
	u8_t                       len = sizeof(p_req->cluster_list);
	zb_ret_t                   zb_err_code;
	zb_bool_t                  use_timeout = ZB_FALSE;
	zb_uint16_t                timeout = ZIGBEE_CLI_MATCH_DESC_RESP_TIMEOUT;
	int                        timeout_offset;
	zb_uint16_t                temp;
	int                        ret_err = 0;

	/* We use p_cluster_list for calls to ZBOSS API but we're not using
	 * p_cluster_list value in any way.
	 */
	(void)(p_cluster_list);

	if (!strcmp(argv[1], "-t") || !strcmp(argv[1], "--timeout")) {
		print_error(shell, "Place option 'timeout' at the end of input parameters",
			    ZB_FALSE);
		return -EINVAL;
	}

	bufid = zb_buf_get_out();
	if (!bufid) {
		print_error(shell, "Failed to execute command (buf alloc failed)",
			    ZB_FALSE);
		return -ENOEXEC;
	}

	p_req = zb_buf_initial_alloc(bufid, sizeof(*p_req));

	if (!parse_hex_u16(argv[1], &temp)) {
		print_error(shell, "Incorrect network address", ZB_FALSE);
		ret_err = -EINVAL;
		goto error;
	}
	p_req->nwk_addr = temp;

	if (!parse_hex_u16(argv[2], &temp)) {
		print_error(shell, "Incorrect address of interest", ZB_FALSE);
		ret_err = -EINVAL;
		goto error;
	}
	p_req->addr_of_interest = temp;

	if (!parse_hex_u16(argv[3], &temp)) {
		print_error(shell, "Incorrect profile id", ZB_FALSE);
		ret_err = -EINVAL;
		goto error;
	}
	p_req->profile_id = temp;

	/* The following functions don't perform any checks on the cluster list
	 * assuming that the CLI isn't abused. In practice the list length
	 * is limited by @p SHELL_ARGC_MAX which defaults to 12 arguments.
	 */

	if (!sscan_uint8(argv[4], &(p_req->num_in_clusters))) {
		print_error(shell, "Incorrect number of input clusters",
			    ZB_FALSE);
		ret_err = -EINVAL;
		goto error;
	}

	if (p_req->num_in_clusters) {
		/* Allocate additional space for cluster IDs. Space for one
		 * cluster ID is already in the structure,
		 * hence we subtract len.
		 */
		p_cluster_list = zb_buf_alloc_right(bufid,
						    p_req->num_in_clusters *
						     sizeof(u16_t) - len);

		/* We have used the space, set to 0 so that space for output
		 * clusters is calculated correctly.
		 */
		len = 0;

		/* Use p_req->cluster_list as destination rather than
		 * p_cluster_list which points to the second element.
		 */
		if (!sscan_cluster_list(argv + 5, p_req->num_in_clusters,
					(u16_t *)p_req->cluster_list)) {

			print_error(shell, "Failed to parse input cluster list",
				    ZB_FALSE);
			ret_err = -EINVAL;
			goto error;
		}
	}

	if (!sscan_uint8(argv[5 + p_req->num_in_clusters],
			 &(p_req->num_out_clusters))) {

		print_error(shell, "Incorrect number of output clusters",
			    ZB_FALSE);
		ret_err = -EINVAL;
		goto error;
	}

	if (p_req->num_out_clusters) {
		p_cluster_list = zb_buf_alloc_right(bufid,
						    p_req->num_out_clusters *
						     sizeof(u16_t) - len);

		if (!sscan_cluster_list(argv + 5 + p_req->num_in_clusters + 1,
					p_req->num_out_clusters,
					(u16_t *)p_req->cluster_list +
					 p_req->num_in_clusters)) {
			print_error(shell, "Failed to parse output cluster list",
				    ZB_FALSE);
			ret_err = -EINVAL;
			goto error;
		}
	}

	/* Now let's check for timeout option. */
	timeout_offset = 6 + p_req->num_in_clusters + p_req->num_out_clusters;

	if (argc == timeout_offset + 2) {
		if (!strcmp(argv[timeout_offset], "-t") ||
		    !strcmp(argv[timeout_offset], "--timeout")) {

			use_timeout = ZB_TRUE;
			if (sscan_uint(argv[timeout_offset + 1],
				       (u8_t*)&timeout, 2, 10) != 1) {

				/* Let's set the timeout to default. */
				timeout = ZIGBEE_CLI_MATCH_DESC_RESP_TIMEOUT;
				shell_warn(shell, "Could not parse the timeout value, setting to default.");
			}
			shell_print(shell, "Timeout set to %d.", timeout);
		}
	}

	p_tsn_cli = get_free_ctx();
	if (!p_tsn_cli) {
		print_error(shell, "Too many ZDO transactions", ZB_FALSE);
		ret_err = -ENOEXEC;
		goto error;
	}

	/* Initialize context and send a request. */
	p_tsn_cli->shell = shell;
	p_tsn_cli->buffer_id = bufid;
	p_tsn_cli->is_broadcast = ZB_NWK_IS_ADDRESS_BROADCAST(p_req->nwk_addr);
	p_tsn_cli->p_zdo_req_fn = zb_zdo_match_desc_req;
	p_tsn_cli->p_zdo_request_cb_fn = cmd_zb_match_desc_cb;

	if (use_timeout || !p_tsn_cli->is_broadcast) {
		p_tsn_cli->ctx_timeout = timeout;
		p_tsn_cli->p_zdo_timeout_cb_fn = cmd_zb_match_desc_timeout;
	} else {
		p_tsn_cli->ctx_timeout = 0;
		p_tsn_cli->p_zdo_timeout_cb_fn = NULL;
	}

	shell_print(shell, "Sending %s request.",
		    p_tsn_cli->is_broadcast ? "broadcast" : "unicast");
	zb_err_code = zigbee_schedule_callback(zb_zdo_req,
					       (p_tsn_cli - m_tsn_ctx));
	if (zb_err_code != RET_OK) {
		print_error(shell, "Unable to schedule zdo request", ZB_FALSE);
		invalidate_ctx(p_tsn_cli);
		ret_err = -ENOEXEC;
		goto error;
	}

	return ret_err;

error:
	zb_buf_free(bufid);
	return ret_err;
}

/**@brief Create or remove a binding between two endpoints on two nodes.
 *
 * @code
 * zdo bind {on,off} <h:source_eui64> <d:source_ep> <h:destination_addr>
 *                   <d:destination_ep> <h:source_cluster_id>
 *                   <h:request_dst_addr>`
 * @endcode
 *
 * Create bound connection between a device identified by `source_eui64` and
 * endpoint `source_ep`, and a device identified by `destination_addr` and
 * endpoint `destination_ep`. The connection is created for ZCL commands and
 * attributes assigned to the ZCL cluster `source_cluster_id` on the
 * `request_dst_addr` node (usually short address corresponding to
 * `source_eui64` argument).
 *
 * Example:
 * @code
 * zdo bind on 0B010E0405060708 1 0B010E4050607080 2 8
 * @endcode
 *
 */
static int cmd_zb_bind(const struct shell *shell, size_t argc, char **argv)
{
	zb_zdo_bind_req_param_t * p_req;
	zdo_tsn_ctx_t           * p_tsn_cli = NULL;
	zb_bufid_t                bufid;
	zb_ret_t                  zb_err_code;
	zb_bool_t                 bind;
	int                       ret_err = 0;

	if (strcmp(argv[0], "on") == 0) {
		bind = ZB_TRUE;
	} else {
		bind = ZB_FALSE;
	}

	bufid = zb_buf_get_out();
	if (!bufid) {
		print_error(shell, "Failed to execute command (buf alloc failed)",
			    ZB_FALSE);
		return -ENOEXEC;
	}

	p_req = ZB_BUF_GET_PARAM(bufid, zb_zdo_bind_req_param_t);

	if (!parse_long_address(argv[1], p_req->src_address)) {
		print_error(shell, "Incorrect EUI64 source address format",
			    ZB_FALSE);
		ret_err = -EINVAL;
		goto error;
	}

	if (!sscan_uint8(argv[2], &(p_req->src_endp))) {
		print_error(shell, "Incorrect source endpoint",
			    ZB_FALSE);
		ret_err = -EINVAL;
		goto error;
	}

	p_req->dst_addr_mode = parse_address(argv[3], &(p_req->dst_address),
					     ADDR_ANY);
	if (p_req->dst_addr_mode == ADDR_INVALID) {
		print_error(shell, "Incorrect destination address format",
			    ZB_FALSE);
		ret_err = -EINVAL;
		goto error;
	}

	if (!sscan_uint8(argv[4], &(p_req->dst_endp))) {
		print_error(shell, "Incorrect destination endpoint",
			    ZB_FALSE);
		ret_err = -EINVAL;
		goto error;
	}

	if (!parse_hex_u16(argv[5], &(p_req->cluster_id))) {
		print_error(shell, "Incorrect cluster ID",
			    ZB_FALSE);
		ret_err = -EINVAL;
		goto error;
	}

	if (!parse_short_address(argv[6], &(p_req->req_dst_addr))) {
		print_error(shell, "Incorrect destination network address for the request",
			    ZB_FALSE);
		ret_err = -EINVAL;
		goto error;
	}

	p_tsn_cli = get_free_ctx();
	if (!p_tsn_cli) {
		print_error(shell, "Too many ZDO transactions", ZB_FALSE);
		ret_err = -ENOEXEC;
		goto error;
	}

	/* Initialize context and send a request. */
	p_tsn_cli->shell = shell;
	p_tsn_cli->buffer_id = bufid;
	if (bind) {
		p_tsn_cli->p_zdo_req_fn = zb_zdo_bind_req;
		p_tsn_cli->p_zdo_request_cb_fn = cmd_zb_bind_unbind_cb;
	} else {
		p_tsn_cli->p_zdo_req_fn = zb_zdo_unbind_req;
		p_tsn_cli->p_zdo_request_cb_fn = cmd_zb_bind_unbind_cb;
	}
	p_tsn_cli->ctx_timeout = ZIGBEE_CLI_BIND_RESP_TIMEOUT;
	p_tsn_cli->p_zdo_timeout_cb_fn = cmd_zb_bind_unbind_timeout;

	zb_err_code = zigbee_schedule_callback(zb_zdo_req,
					       (p_tsn_cli - m_tsn_ctx));
	if (zb_err_code != RET_OK) {
		print_error(shell, "Unable to schedule zdo request", ZB_FALSE);
		ret_err = -ENOEXEC;
		goto error;
	}

	return ret_err;

error:
	if (p_tsn_cli != NULL) {
		invalidate_ctx(p_tsn_cli);
	}
	zb_buf_free(bufid);

	return ret_err;
}

/**@brief Resolve eui64 address to a short network address.
 *
 * @code
 * zdo nwk_addr <h:eui64>
 * @endcode
 *
 * Example:
 * @code
 * zdo nwk_addr 0B010E0405060708
 * @endcode
 *
 */
static int cmd_zb_nwk_addr(const struct shell *shell, size_t argc, char **argv)
{
	zb_zdo_nwk_addr_req_param_t * p_req;
	zdo_tsn_ctx_t               * p_tsn_cli = NULL;
	zb_bufid_t                    bufid;
	zb_ret_t                      zb_err_code;
	int                           ret_err = 0;

	bufid = zb_buf_get_out();
	if (!bufid) {
		print_error(shell, "Failed to execute command (buf alloc failed)",
			    ZB_FALSE);
		return -ENOEXEC;
	}

	p_req = ZB_BUF_GET_PARAM(bufid, zb_zdo_nwk_addr_req_param_t);

	if (!parse_long_address(argv[1], p_req->ieee_addr)) {
		print_error(shell, "Incorrect EUI64 address format",
			    ZB_FALSE);
		ret_err = -EINVAL;
		goto error;
	}

	p_tsn_cli = get_free_ctx();
	if (!p_tsn_cli) {
		print_error(shell, "Too many ZDO transactions",
			    ZB_FALSE);
		ret_err = -ENOEXEC;
		goto error;
	}

	/* Construct network address request. */
	p_req->dst_addr     = ZB_NWK_BROADCAST_ALL_DEVICES;
	p_req->request_type = ZB_ZDO_SINGLE_DEVICE_RESP;
	p_req->start_index  = 0;

	/* Initialize context and send a request. */
	p_tsn_cli->shell = shell;
	p_tsn_cli->buffer_id = bufid;
	p_tsn_cli->p_zdo_req_fn = zb_zdo_nwk_addr_req;
	p_tsn_cli->p_zdo_request_cb_fn = cmd_zb_nwk_addr_cb;
	p_tsn_cli->ctx_timeout = ZIGBEE_CLI_NWK_ADDR_RESP_TIMEOUT;
	p_tsn_cli->p_zdo_timeout_cb_fn = cmd_zb_nwk_addr_timeout;

	zb_err_code = zigbee_schedule_callback(zb_zdo_req,
					       (p_tsn_cli - m_tsn_ctx));
	if (zb_err_code != RET_OK) {
		print_error(shell, "Unable to schedule zdo request",
			    ZB_FALSE);
		ret_err = -ENOEXEC;
		goto error;
	}

	return ret_err;

error:
	if (p_tsn_cli != NULL) {
		invalidate_ctx(p_tsn_cli);
	}
	zb_buf_free(bufid);

	return ret_err;
}

/**@brief Resolve EUI64 by sending IEEE address request.
 *
 * @code
 * zdo ieee_addr <h:short_addr>
 * @endcode
 *
 */
static int cmd_zb_ieee_addr(const struct shell *shell, size_t argc, char **argv)
{
	zb_zdo_ieee_addr_req_param_t * p_req = NULL;
	zdo_tsn_ctx_t                * p_tsn_cli = NULL;
	zb_bufid_t                     bufid;
	zb_ret_t                       zb_err_code;
	zb_uint16_t                    addr;
	int                            ret_err = 0;

	bufid = zb_buf_get_out();
	if (!bufid) {
		print_error(shell, "Failed to execute command (buf alloc failed)",
			    ZB_FALSE);
		return -ENOEXEC;
	}

	/* Create new IEEE address request and fill with default values. */
	p_req = ZB_BUF_GET_PARAM(bufid, zb_zdo_ieee_addr_req_param_t);
	p_req->start_index  = 0;
	p_req->request_type = 0;

	if (!parse_hex_u16(argv[1], &addr)) {
		print_error(shell, "Incorrect network address", ZB_FALSE);
		ret_err = -EINVAL;
		goto error;
	}
	p_req->nwk_addr = addr;
	p_req->dst_addr = p_req->nwk_addr;

	p_tsn_cli = get_free_ctx();
	if (!p_tsn_cli) {
		print_error(shell, "Too many ZDO transactions", ZB_FALSE);
		ret_err = -ENOEXEC;
		goto error;
	}

	/* Initialize context and send a request. */
	p_tsn_cli->shell = shell;
	p_tsn_cli->buffer_id = bufid;
	p_tsn_cli->p_zdo_req_fn = zb_zdo_ieee_addr_req;
	p_tsn_cli->p_zdo_request_cb_fn = cmd_zb_ieee_addr_cb;
	p_tsn_cli->ctx_timeout = ZIGBEE_CLI_IEEE_ADDR_RESP_TIMEOUT;
	p_tsn_cli->p_zdo_timeout_cb_fn = cmd_zb_ieee_addr_timeout;

	zb_err_code = zigbee_schedule_callback(zb_zdo_req,
					       (p_tsn_cli - m_tsn_ctx));
	if (zb_err_code != RET_OK) {
		print_error(shell, "Unable to schedule zdo request", ZB_FALSE);
		ret_err = -ENOEXEC;
		goto error;
	}

	return ret_err;

error:
	if (p_tsn_cli != NULL) {
		invalidate_ctx(p_tsn_cli);
	}
	zb_buf_free(bufid);

	return ret_err;
}

/**@brief Get the short 16-bit address of the Zigbee device.
 *
 * @code
 * > zdo short
 * 0000
 * Done
 * @endcode
 */
static int cmd_zb_short(const struct shell *shell, size_t argc, char **argv)
{
	(void)(argv);

	zb_ieee_addr_t addr;
	zb_uint16_t short_addr;
	int i;

	zb_get_long_address(addr);

	short_addr = zb_address_short_by_ieee(addr);
	if (short_addr != ZB_UNKNOWN_SHORT_ADDR) {
		/* We got a valid address. */
		for (i = sizeof(zb_uint16_t) - 1; i >= 0; i--) {
			shell_fprintf(shell, SHELL_NORMAL, "%02x",
				      *((zb_uint8_t*)(&short_addr) + i));
		}

		print_done(shell, ZB_TRUE);
		return 0;
	} else {
		/* Most probably there was no network to join. */
		print_error(shell, "Check if device was commissioned",
			    ZB_FALSE);
		return -ENOEXEC;
	}
}

/**@brief Get or set the EUI64 address of the Zigbee device.
 *
 * @code
 * > zdo eui64 [<h:eui64>]
 * 0b010eaafd745dfa
 * Done
 * @endcode
 */
static int cmd_zb_eui64(const struct shell *shell, size_t argc, char **argv)
{
	zb_ieee_addr_t addr;

	(void)(argv);

	if (argc == 2) {
		if (parse_long_address(argv[1], addr)) {
			zb_set_long_address(addr);
		} else {
			print_error(shell, "Incorrect EUI64 address format",
				    ZB_FALSE);
			return -EINVAL;
		}
	} else {
		zb_get_long_address(addr);
	}

	print_eui64(shell, addr);
	/* Prepend newline because `print_eui64` does not print LF. */
	print_done(shell, ZB_TRUE);

	return 0;
}

/**@brief Callback called, when mgmt_leave operation takes too long
 * @param tsn[in] tsn value obtained as result of zdo_mgmt_leave_req,
 *                transaction sequence number
 */
static void cmd_zb_mgmt_leave_timeout_cb(zb_uint8_t tsn)
{
	zdo_tsn_ctx_t * p_tsn_ctx = get_ctx_by_tsn(tsn);

	if (p_tsn_ctx == NULL) {
		return;
	}

	print_error(p_tsn_ctx->shell, "mgmt_leave request timed out", ZB_FALSE);

	invalidate_ctx(p_tsn_ctx);
}

/**@brief Callback called when response to mgmt_leave is received
 *
 * @param bufid[in] zboss buffer reference
 */
static void cmd_zb_mgmt_leave_cb(zb_bufid_t bufid)
{
	zb_zdo_mgmt_leave_res_t *p_resp;
	zdo_tsn_ctx_t           *p_tsn_ctx;

	p_resp = (zb_zdo_mgmt_leave_res_t*)zb_buf_begin(bufid);
	p_tsn_ctx = get_ctx_by_tsn(p_resp->tsn);
	if (p_tsn_ctx != NULL) {
		zb_ret_t zb_err_code;

		zb_err_code = ZB_SCHEDULE_APP_ALARM_CANCEL(
					cmd_zb_mgmt_leave_timeout_cb,
					p_resp->tsn);
		if (zb_err_code != RET_OK) {
			print_error(p_tsn_ctx->shell, "Unable to cancel timeout timer",
				    ZB_TRUE);
		}

		if (p_resp->status == ZB_ZDP_STATUS_SUCCESS) {
			print_done(p_tsn_ctx->shell, ZB_FALSE);
		} else {
			shell_error(p_tsn_ctx->shell, "Error: Unable to remove device. Status: %u",
				    (u32_t)p_resp->status);
		}

		invalidate_ctx(p_tsn_ctx);
	}

	zb_buf_free(bufid);
}

/**@brief Parses command line arguments for zdo mgmt_leave comand
 * @param   p_req[out]    Request do be filled in according to command line
 *                        arguments.
 * @param   shell[in]     Pointer to cli instance, used to produce errors
 *                        if neccessary.
 * @param   argc[in]      Number of arguments in argv.
 * @param   argv[in]      Arguments from cli to the command.
 *
 * @return  true, if arguments were parsed correctly and p_req
 *          has been filled up <br> false, if arguments were incorrect.
 *
 * @sa @ref cmd_zb_mgmt_leave
 */
static bool cmd_zb_mgmt_leave_parse(zb_zdo_mgmt_leave_param_t *p_req,
				    const struct shell *shell, size_t argc,
				    char **argv)
{
	size_t      arg_idx;
	zb_uint16_t addr;

	ZB_MEMSET(p_req, 0, sizeof(*p_req));

	arg_idx = 1U;   /* Let it be index of the first argument to parse. */
	if (arg_idx >= argc) {
		print_error(shell, "Lack of dst_addr parameter", ZB_FALSE);
		return false;
	}

	if (parse_hex_u16(argv[arg_idx], &addr) != 1) {
		print_error(shell, "Incorrect dst_addr", ZB_FALSE);
		return false;
	}

	p_req->dst_addr = addr;
	arg_idx++;

	/* Try parse device_address. */
	if (arg_idx < argc) {
		const char *curr_arg = argv[arg_idx];
		if (curr_arg[0] != '-') {
			if (!parse_long_address(curr_arg,
						p_req->device_address)) {
				print_error(shell, "Incorrect device_address",
					    ZB_FALSE);
				return false;
			}

			arg_idx++;
		} else {
			/* No device_address field. */
		}
	}

	/* Parse optional fields. */
	while (arg_idx < argc) {
		const char *curr_arg = argv[arg_idx];
		if (strcmp(curr_arg, "--children") == 0) {
			p_req->remove_children = ZB_TRUE;
		} else if (strcmp(curr_arg, "--rejoin") == 0) {
			p_req->rejoin = ZB_TRUE;
		} else {
			print_error(shell, "Incorrect argument", ZB_FALSE);
			return false;
		}
		arg_idx++;
	}


	return true;
}

/**@brief Send a request to a remote device in order to leave network
 *        through zdo mgmt_leave_req (see spec. 2.4.3.3.5)
 *
 * @code
 * zdo mgmt_leave <h:16-bit dst_addr> [h:device_address eui64]
 *                [--children] [--rejoin]
 * @endcode
 *
 * Send @c mgmt_leave_req to a remote node specified by @c dst_addr.
 * If @c device_address is omitted or it has value @c 0000000000000000,
 * the remote device at address @c dst_addr will remove itself from the network.
 * If @c device_address has other value, it must be a long address
 * corresponding to @c dst_addr or a long address of child node of @c dst_addr.
 * The request is sent with <em>Remove Children</em> and <em>Rejoin</em> flags
 * set to @c 0 by default. Use options:
 * @c \--children or @c \--rejoin do change respective flags to @c 1.
 * For more details, see section 2.4.3.3.5 of the specification.
 *
 * Examples:
 * @code
 * zdo mgmt_leave 0x1234
 * @endcode
 * Sends @c mgmt_leave_req to the device with short address @c 0x1234,
 * asking it to remove itself from the network. @n
 * @code
 * zdo mgmt_leave 0x1234 --rejoin
 * @endcode
 * Sends @c mgmt_leave_req to device with short address @c 0x1234, asking it
 * to remove itself from the network and perform rejoin.@n
 * @code
 * zdo mgmt_leave 0x1234 0b010ef8872c633e
 * @endcode
 * Sends @c mgmt_leave_req to device with short address @c 0x1234, asking it
 * to remove device @c 0b010ef8872c633e from the network.
 * If the target device with short address @c 0x1234 has also a long address
 * @c 0b010ef8872c633e, it will remove itself from the network
 * If the target device with short address @c 0x1234 has a child with long
 * address @c 0b010ef8872c633e, it will remove the child from the network.@n
 * @code
 * zdo mgmt_leave 0x1234 --children
 * @endcode
 * Sends @c mgmt_leave_req to the device with short address @c 0x1234,
 * asking it to remove itself and all its children from the network.@n
 */
static int cmd_zb_mgmt_leave(const struct shell *shell, size_t argc,
			     char **argv)
{
	zb_zdo_mgmt_leave_param_t *p_req;

	zb_bufid_t     bufid     = 0;
	zdo_tsn_ctx_t *p_tsn_cli = NULL;
	zb_ret_t       zb_err_code;

	bufid = zb_buf_get_out();
	if (bufid == 0) {
		print_error(shell, "Failed to execute command (buf alloc failed)",
			    ZB_FALSE);
		goto error;
	}

	p_req = ZB_BUF_GET_PARAM(bufid, zb_zdo_mgmt_leave_param_t);
	if (!cmd_zb_mgmt_leave_parse(p_req, shell, argc, argv)) {
		/* The error message has already been printed
		 * by cmd_zb_mgmt_leave_parse.
		 */
		zb_buf_free(bufid);
		return -EINVAL;
	}

	p_tsn_cli = get_free_ctx();
	if (p_tsn_cli == NULL) {
		print_error(shell, "Too many ZDO transactions", ZB_FALSE);
		goto error;
	}

	/* Initialize context and send a request. */
	p_tsn_cli->shell = shell;
	p_tsn_cli->buffer_id = bufid;
	p_tsn_cli->p_zdo_req_fn = zdo_mgmt_leave_req;
	p_tsn_cli->p_zdo_request_cb_fn = cmd_zb_mgmt_leave_cb;
	p_tsn_cli->ctx_timeout = ZIGBEE_CLI_MGMT_LEAVE_RESP_TIMEOUT;
	p_tsn_cli->p_zdo_timeout_cb_fn = cmd_zb_mgmt_leave_timeout_cb;

	zb_err_code = zigbee_schedule_callback(zb_zdo_req,
					       (p_tsn_cli - m_tsn_ctx));
	if (zb_err_code != RET_OK) {
		print_error(shell, "Unable to schedule zdo request", ZB_FALSE);
		goto error;
	}

	return 0;

error:
	if (bufid != 0) {
		zb_buf_free(bufid);
	}
	if (p_tsn_cli != NULL) {
		invalidate_ctx(p_tsn_cli);
	}
	return -ENOEXEC;
}

/**@brief Request timeout callback.
 *
 * @param tsn[in] ZDO transaction sequence number returned by request.
 */
static void ctx_timeout_cb(zb_uint8_t tsn)
{
	zdo_tsn_ctx_t *p_tsn_ctx = get_ctx_by_tsn(tsn);

	if (p_tsn_ctx == NULL) {
		LOG_ERR("Unable to find context for ZDO request %u.", tsn);
		return;
	}

	shell_error(p_tsn_ctx->shell, "Error: ZDO request %u timed out.", tsn);
	invalidate_ctx(p_tsn_ctx);
}

/**@brief A generic ZDO request callback.
 *
 * This will print status code for the message and, if not overridden, free
 * resources associated with the request.
 *
 * @param bufid[in] ZBOSS buffer id
 */
static void zdo_request_cb(zb_bufid_t bufid)
{
	zb_zdo_callback_info_t *p_resp;
	zdo_tsn_ctx_t          *p_tsn_ctx;
	bool                    is_request_complete;
	zb_ret_t                zb_err_code;

	p_resp = (zb_zdo_callback_info_t *)zb_buf_begin(bufid);
	p_tsn_ctx = get_ctx_by_tsn(p_resp->tsn);
	if (p_tsn_ctx == NULL) {
		LOG_ERR("Unable to find context for TSN %d", p_resp->tsn);
		zb_buf_free(bufid);
		return;
	}

	zb_err_code = ZB_SCHEDULE_APP_ALARM_CANCEL(ctx_timeout_cb, p_resp->tsn);
	ZB_ERROR_CHECK(zb_err_code);

	/* Call custom callback if set. If the callback returns false,
	 * i.e.,request isn't complete, then don't print status,
	 * invalidate context, or free input buffer. Request might not be
	 * complete if more messages must be send, e.g., to get multiple
	 * table entries from a remote device.
	 */
	if (p_tsn_ctx->p_cb_fn != NULL) {
		is_request_complete = p_tsn_ctx->p_cb_fn(p_tsn_ctx, bufid);
	} else {
		is_request_complete = true;
	}

	if (is_request_complete) {
		/* We can free all resources. */
		if (p_resp->status == ZB_ZDP_STATUS_SUCCESS) {
			shell_print(p_tsn_ctx->shell, "ZDO request %u complete",
				    p_resp->tsn);
			print_done(p_tsn_ctx->shell, ZB_FALSE);
		} else {
			shell_error(p_tsn_ctx->shell, "Error: ZDO request %u failed with status %u",
				    (u32_t)p_resp->tsn, (u32_t)p_resp->status);
		}
	} else {
		/* The request isn't complete, i.e., another ZDO transaction
		 * went out, hence we need to reschedule a timeout callback.
		 */
		zb_err_code = ZB_SCHEDULE_APP_ALARM(
					ctx_timeout_cb, p_tsn_ctx->tsn,
					ZIGBEE_CLI_MGMT_LEAVE_RESP_TIMEOUT *
					 ZB_TIME_ONE_SECOND);
		if (zb_err_code != RET_OK) {
			print_error(p_tsn_ctx->shell, "Unable to schedule timeout callback",
				    ZB_FALSE);
			is_request_complete = true;
		}
	}

	if (is_request_complete) {
		invalidate_ctx(p_tsn_ctx);
		zb_buf_free(bufid);
	}
}

/**@brief Prints one binding table record.
 *
 * @param[out] shell     The CLI the output is printed to.
 * @param[in]  idx       Record index in binding table.
 * @param[in]  p_record  Record to be printed out.
 */
static void print_bind_resp_record(const struct shell *shell, u32_t idx,
				   const zb_zdo_binding_table_record_t *p_record)
{
	char ieee_address_str[sizeof(p_record->src_address)*2U + 1U];

	if (ieee_addr_to_str(ieee_address_str, sizeof(ieee_address_str),
			     p_record->src_address) <= 0) {
		strcpy(ieee_address_str, "(error)         ");
	}
	/* Ensure null-terminated string. */
	ieee_address_str[sizeof(ieee_address_str)-1U] = '\0';

	/* Note: Fields in format string are scattered to match position
	 * in the header, printed by print_bind_resp_records_header.
	 */
	shell_fprintf(shell, SHELL_NORMAL, "[%3u] %s      %3u     0x%04x",
		      (u32_t)idx, ieee_address_str, (u32_t)p_record->src_endp,
		      (u32_t)p_record->cluster_id);

	shell_fprintf(shell, SHELL_NORMAL, "           %3u ",
		      (u32_t)p_record->dst_addr_mode);

	switch (p_record->dst_addr_mode) {
		/* 16-bit group address for DstAddr and DstEndp not present. */
		case ZB_APS_ADDR_MODE_16_GROUP_ENDP_NOT_PRESENT:
			shell_fprintf(shell, SHELL_NORMAL, "          0x%4x      N/A",
				      (u32_t)p_record->dst_address.addr_short);
			break;

		/* 64-bit extended address for DstAddr and DstEndp present. */
		case ZB_APS_ADDR_MODE_64_ENDP_PRESENT:
			if (ieee_addr_to_str(
				ieee_address_str,
				sizeof(ieee_address_str),
				p_record->dst_address.addr_long) <= 0) {

				strcpy(ieee_address_str, "(error)         ");
			}
			/* Ensure null-terminated string. */
			ieee_address_str[sizeof(ieee_address_str)-1U] = '\0';

			shell_fprintf(shell, SHELL_NORMAL, "%s      %3u",
				      ieee_address_str,
				      (u32_t)p_record->dst_endp);
			break;

		default:
			/* This should not happen, as the above case values
			 * are the only ones allowed by R21 Zigbee spec.
			 */
			shell_fprintf(shell, SHELL_NORMAL, "            N/A      N/A");
			break;
	}

	shell_print(shell, "");
}

/**@brief   Prints header for binding records table
 * @param[out] shell    The CLI the output is printed to.
 */
static void print_bind_resp_records_header(const struct shell *shell)
{
	/* Note: Position of fields matches corresponding fields printed
	 * by print_bind_resp_record.
	 */
	shell_print(shell, "[idx] src_address      src_endp cluster_id dst_addr_mode dst_addr         dst_endp");
}

/**@brief   Prints records of binding table received from zdo_mgmt_bind_resp
 * @param[out] shell    The CLI the output is printed to.
 * @param[in]  p_resp   Response received from remote device to be printed out.
 *
 * @note Records of type @ref zb_zdo_binding_table_record_t are located
 *       just after the @ref zb_zdo_mgmt_bind_resp_t structure pointed
 *       by p_resp parameter.
 */
static void print_bind_resp(const struct shell *shell,
			    const zb_zdo_mgmt_bind_resp_t * p_resp)
{
	u32_t next_start_index = ((u32_t)p_resp->start_index +
				  p_resp->binding_table_list_count);

	const zb_zdo_binding_table_record_t *p_record;
	p_record = (const zb_zdo_binding_table_record_t *)(p_resp + 1);

	for (u32_t idx = p_resp->start_index; idx < next_start_index; ++idx) {
		++p_record;
		print_bind_resp_record(shell, idx, p_record);
	}
}

/**@brief Callback terminating single mgmt_bind_req transaction
 * @note
 * When the binding table is too large to fit into a single mgmt_bind_rsp
 * command frame, this function will issue a new mgmt_bind_req_t
 * with start_index increased by the number of just received entries to download
 * remaining part of the binding table. This process may involve several round
 * trips of mgmt_bind_req followed by mgmt_bind_rsp until the whole binding
 * table is downloaded.
 *
 * @param bufid     Reference to ZBOSS buffer (as required by Zigbee stack API)
 */
static void cmd_zb_mgmt_bind_cb(zb_bufid_t bufid)
{
	zb_zdo_mgmt_bind_resp_t *p_resp;
	zdo_tsn_ctx_t           *p_tsn_ctx;

	p_resp = (zb_zdo_mgmt_bind_resp_t*)zb_buf_begin(bufid);
	p_tsn_ctx = get_ctx_by_tsn(p_resp->tsn);

	if (p_tsn_ctx != NULL) {
		if (p_resp->status == ZB_ZDP_STATUS_SUCCESS) {
			if ((p_resp->start_index ==
			     p_tsn_ctx->cmd_ctx.req_seq.start_index)) {
				print_bind_resp_records_header(
					p_tsn_ctx->shell);
			}
			print_bind_resp(p_tsn_ctx->shell, p_resp);

			u32_t next_start_index = p_resp->start_index;
			next_start_index += p_resp->binding_table_list_count;

			if (next_start_index < p_resp->binding_table_entries &&
				(next_start_index < 0xFFU) &&
				(p_resp->binding_table_list_count != 0U)) {

				/* We have more entries to get. */
				(void)(zb_buf_reuse(bufid));
				zb_zdo_mgmt_bind_param_t *p_req =
					ZB_BUF_GET_PARAM(
						bufid,
						zb_zdo_mgmt_bind_param_t);
				p_req->dst_addr =
					p_tsn_ctx->cmd_ctx.req_seq.dst_addr;
				p_req->start_index = next_start_index;

				p_tsn_ctx->tsn = zb_zdo_mgmt_bind_req(
							bufid,
							cmd_zb_mgmt_bind_cb);
				if (p_tsn_ctx->tsn == ZB_ZDO_INVALID_TSN)
				{
					print_error(p_tsn_ctx->shell, "Failed to send request",
						    ZB_FALSE);
					goto finish;
				}

				/* bufid reused, mark NULL not to free it. */
				bufid     = 0;
				/* p_tsn_ctx reused, set NULL not to free it. */
				p_tsn_ctx = NULL;
			} else {
				shell_print(
					p_tsn_ctx->shell,
					"Total entries for the binding table: %u",
					(u32_t)p_resp->binding_table_entries);
				print_done(p_tsn_ctx->shell, ZB_FALSE);
			}
		} else {
			shell_error(p_tsn_ctx->shell, "Error: Unable to get binding table. Status: %u",
				    (u32_t)p_resp->status);
		}
	}

finish:
	if (bufid != 0) {
		zb_buf_free(bufid);
	}

	if (p_tsn_ctx != NULL) {
		invalidate_ctx(p_tsn_ctx);
	}
}

/**@brief Send a request to a remote device in order to read the binding table
 *        through zdo mgmt_bind_req (see spec. 2.4.3.3.4)
 *
 * @note If whole binding table does not fit into single @c mgmt_bind_resp
 *       frame, the request initiates a series of
 * requests performing full binding table download.
 *
 * @code
 * zdo mgmt_bind <h:short> [d:start_index]
 * @endcode
 *
 * Example:
 * @code
 * zdo mgmt_bind 0x1234
 * @endcode
 * Sends @c mgmt_bind_req to the device with short address @c 0x1234,
 * asking it to return its binding table.
 */
static int cmd_zb_mgmt_bind(const struct shell *shell, size_t argc, char **argv)
{
	size_t                     arg_idx = 1U;
	zb_zdo_mgmt_bind_param_t * p_req;
	int                        ret_err = 0;

	zdo_tsn_ctx_t * p_tsn_ctx = NULL;
	zb_bufid_t      bufid     = 0;
	zb_ret_t        zb_err_code;

	p_tsn_ctx = get_free_ctx();
	if (p_tsn_ctx == NULL) {
		print_error(shell, "Too many ZDO transactions", ZB_FALSE);
		ret_err = -ENOEXEC;
		goto error;
	}
	p_tsn_ctx->shell = shell;

	if (arg_idx < argc) {
		if (!parse_short_address(
			argv[arg_idx],
			&(p_tsn_ctx->cmd_ctx.req_seq.dst_addr))) {

			print_error(shell, "Incorrect dst_addr", ZB_FALSE);
			ret_err = -EINVAL;
			goto error;
		}
		arg_idx++;
	} else {
		print_error(shell, "dst_addr parameter missing", ZB_FALSE);
		ret_err = -EINVAL;
		goto error;
	}

	if (arg_idx < argc) {
		if (!sscan_uint8(argv[arg_idx],
				 &p_tsn_ctx->cmd_ctx.req_seq.start_index)) {
			print_error(shell, "Incorrect start_index", ZB_FALSE);
			ret_err = -EINVAL;
			goto error;
		}
		arg_idx++;
	} else {
		/* This parameter was optional, no error. */
		p_tsn_ctx->cmd_ctx.req_seq.start_index = 0;
	}

	if (arg_idx < argc) {
		print_error(shell, "Unexpected extra parameters", ZB_FALSE);
		ret_err = -EINVAL;
		goto error;
	}

	bufid = zb_buf_get_out();
	if (!bufid) {
		print_error(shell, "Failed to execute command (buf alloc failed)",
			    ZB_FALSE);
		ret_err = -ENOEXEC;
		goto error;
	}

	p_req = ZB_BUF_GET_PARAM(bufid, zb_zdo_mgmt_bind_param_t);
	ZB_BZERO(p_req, sizeof(*p_req));
	p_req->start_index = p_tsn_ctx->cmd_ctx.req_seq.start_index;
	p_req->dst_addr    = p_tsn_ctx->cmd_ctx.req_seq.dst_addr;

	/* Initialize context and send a request. */
	p_tsn_ctx->shell = shell;
	p_tsn_ctx->buffer_id = bufid;
	p_tsn_ctx->p_zdo_req_fn = zb_zdo_mgmt_bind_req;
	p_tsn_ctx->p_zdo_request_cb_fn = cmd_zb_mgmt_bind_cb;
	p_tsn_ctx->ctx_timeout = 0;
	p_tsn_ctx->p_zdo_timeout_cb_fn = NULL;

	zb_err_code = zigbee_schedule_callback(zb_zdo_req,
					       (p_tsn_ctx - m_tsn_ctx));
	if (zb_err_code != RET_OK) {
		print_error(shell, "Unable to schedule zdo request", ZB_FALSE);
		ret_err = -ENOEXEC;
		goto error;
	}

	return ret_err;

error:
	if (bufid != 0) {
		zb_buf_free(bufid);
	}
	if (p_tsn_ctx != NULL) {
		invalidate_ctx(p_tsn_ctx);
	}
	return ret_err;
}

/**@brief Callback for a single mgmt_lqi_req transaction
 *
 * @note
 * When the lqi table is too large to fit into a single mgmt_bind_rsp command
 * frame, this function will issue a new mgmt_lqi_req to download reminder of
 * the table. This process may involve several round trips of mgmt_lqi_req
 * followed by mgmt_lqi_resp until the whole binding table is downloaded.
 *
 * @param bufid     Reference to ZBOSS buffer (as required by Zigbee stack API)
 */
static bool zdo_mgmt_lqi_cb(struct zdo_tsn_ctx * p_tsn_ctx, zb_bufid_t bufid)
{
	bool                           result = true;
	zb_zdo_mgmt_lqi_resp_t         *p_resp;
	zb_zdo_neighbor_table_record_t *p_record;

	p_resp = (zb_zdo_mgmt_lqi_resp_t *)zb_buf_begin(bufid);

	if (p_resp->status == ZB_ZDP_STATUS_SUCCESS) {
		if (p_resp->start_index ==
		    p_tsn_ctx->cmd_ctx.req_seq.start_index) {
			shell_print(p_tsn_ctx->shell, "[idx] ext_pan_id       ext_addr         " "short_addr flags permit_join depth lqi");
		}

		p_record = (zb_zdo_neighbor_table_record_t *)((u8_t *)p_resp +
							      sizeof(*p_resp));

		for (u8_t i = 0; i < p_resp->neighbor_table_list_count; i++) {
			p_record++;
			shell_fprintf(p_tsn_ctx->shell, SHELL_NORMAL, "[%3u] ",
				      p_resp->start_index + i);

			print_eui64(p_tsn_ctx->shell, p_record->ext_pan_id);

			shell_fprintf(p_tsn_ctx->shell, SHELL_NORMAL, " ");
			print_eui64(p_tsn_ctx->shell, p_record->ext_addr);

			shell_print(p_tsn_ctx->shell, " 0x%04x     0x%02x  " "%u           %u     %u",
				    p_record->network_addr,
				    p_record->type_flags, p_record->permit_join,
				    p_record->depth, p_record->lqi);
		}

		u16_t next_index = (p_resp->start_index +
				    p_resp->neighbor_table_list_count);

		/* Get next portion of lqi table if needed. */
		if ((next_index < p_resp->neighbor_table_entries) &&
			(next_index < 0xff) &&
			(p_resp->neighbor_table_list_count > 0)) {
			zb_zdo_mgmt_lqi_param_t * p_req;

			(void)(zb_buf_reuse(bufid));
			p_req = ZB_BUF_GET_PARAM(bufid,
						 zb_zdo_mgmt_lqi_param_t);

			p_req->start_index = next_index;
			p_req->dst_addr = p_tsn_ctx->cmd_ctx.req_seq.dst_addr;

			p_tsn_ctx->tsn = zb_zdo_mgmt_lqi_req(bufid,
							     zdo_request_cb);
			if (p_tsn_ctx->tsn != ZB_ZDO_INVALID_TSN) {
				/* The request requires further communication,
				 * hence the outer callback shoudn't free
				 * resources.
				 */
				result = false;
			}
		}
	}

	return result;
}

/**@brief Send a ZDO Mgmt_Lqi_Req command to a remote device.
 *
 * @code
 * zdo mgmt_lqi <h:short> [d:start index]
 * @endcode
 *
 * Example:
 * @code
 * zdo mgmt_lqi 0x1234
 * @endcode
 * Sends @c mgmt_lqi_req to the device with short address @c 0x1234,
 * asking it to return its neighbor table.
 */
static int cmd_zb_mgmt_lqi(const struct shell *shell, size_t argc, char **argv)
{
	zb_zdo_mgmt_lqi_param_t * p_req;
	zb_bufid_t                bufid     = 0;
	zdo_tsn_ctx_t           * p_tsn_cli = NULL;
	int                       ret_err   = 0;
	zb_ret_t                  zb_err_code;

	bufid = zb_buf_get_out();
	if (!bufid) {
		print_error(shell, "Failed to allocate request buffer",
			    ZB_FALSE);
		ret_err = -ENOEXEC;
		goto error;
	}

	p_req = ZB_BUF_GET_PARAM(bufid, zb_zdo_mgmt_lqi_param_t);

	if (!parse_short_address(argv[1], &(p_req->dst_addr))) {
		print_error(shell, "Failed to parse destination address",
			    ZB_FALSE);
		ret_err = -EINVAL;
		goto error;
	}

	if (argc >= 3) {
		if (!sscan_uint8(argv[2], &(p_req->start_index))) {
			print_error(shell, "Failed to parse start index",
				    ZB_FALSE);
			ret_err = -EINVAL;
			goto error;
		}
	} else {
		p_req->start_index = 0;
	}

	p_tsn_cli = get_free_ctx();
	if (p_tsn_cli == NULL) {
		print_error(shell, "Too many ZDO transactions", ZB_FALSE);
		ret_err = -ENOEXEC;
		goto error;
	}

	/* Initialize context and send a request. */
	p_tsn_cli->shell = shell;
	p_tsn_cli->buffer_id = bufid;
	p_tsn_cli->p_cb_fn  = zdo_mgmt_lqi_cb;
	p_tsn_cli->p_zdo_req_fn = zb_zdo_mgmt_lqi_req;
	p_tsn_cli->p_zdo_request_cb_fn = zdo_request_cb;
	p_tsn_cli->ctx_timeout = ZIGBEE_CLI_MGMT_LEAVE_RESP_TIMEOUT;
	p_tsn_cli->p_zdo_timeout_cb_fn = ctx_timeout_cb;

	zb_err_code = zigbee_schedule_callback(zb_zdo_req,
					       (p_tsn_cli - m_tsn_ctx));
	if (zb_err_code != RET_OK) {
		print_error(shell, "Unable to schedule zdo request", ZB_FALSE);
		ret_err = -ENOEXEC;
		goto error;
	}

	return ret_err;

error:
	if (bufid != 0) {
		zb_buf_free(bufid);
	}
	if (p_tsn_cli != NULL) {
		invalidate_ctx(p_tsn_cli);
	}

	return ret_err;
}

SHELL_STATIC_SUBCMD_SET_CREATE(sub_bind,
	SHELL_CMD_ARG(on, NULL, BIND_ON_HELP, cmd_zb_bind, 7, 0),
	SHELL_CMD_ARG(off, NULL, BIND_OFF_HELP, cmd_zb_bind, 7, 0),
	SHELL_SUBCMD_SET_END);

SHELL_STATIC_SUBCMD_SET_CREATE(sub_zdo,
	SHELL_CMD_ARG(active_ep, NULL, ACTIVE_EP_HELP, cmd_zb_active_ep, 2, 0),
	SHELL_CMD_ARG(simple_desc_req, NULL, SIMPLE_DESC_HELP, cmd_zb_simple_desc, 3, 0),
	SHELL_CMD_ARG(match_desc, NULL, MATCH_DESC_HELP, cmd_zb_match_desc, 6, SHELL_OPT_ARG_CHECK_SKIP),
	SHELL_CMD_ARG(nwk_addr, NULL, NWK_ADDR_HELP, cmd_zb_nwk_addr, 2, 0),
	SHELL_CMD_ARG(ieee_addr, NULL, IEEE_ADDR_HELP, cmd_zb_ieee_addr, 2, 0),
	SHELL_CMD_ARG(eui64, NULL, EUI64_HELP, cmd_zb_eui64, 1, 1),
	SHELL_CMD_ARG(short, NULL, "Get the short address of the node.", cmd_zb_short, 1, 0),
	SHELL_CMD(bind, &sub_bind, "Create/remove the binding entry in the remote node", NULL),
	SHELL_CMD_ARG(mgmt_bind, NULL, MGMT_BIND_HELP, cmd_zb_mgmt_bind, 2, 1),
	SHELL_CMD_ARG(mgmt_leave, NULL, MGMT_LEAVE_HELP, cmd_zb_mgmt_leave, 2, 3),
	SHELL_CMD_ARG(mgmt_lqi, NULL, MGMT_LQI_HELP, cmd_zb_mgmt_lqi, 2, 1),
	SHELL_SUBCMD_SET_END);

SHELL_CMD_REGISTER(zdo, &sub_zdo, "ZDO manipulation", NULL);
