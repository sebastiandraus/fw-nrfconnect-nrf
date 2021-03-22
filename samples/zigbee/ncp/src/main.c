/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/** @file
 *  @brief Zigbee Network Co-processor sample
 */

#include <drivers/uart.h>
#include <usb/usb_device.h>
#include <logging/log.h>
#include <zb_nrf_platform.h>
#include <zb_osif_ext.h>

/* Requried by HCI UART sample. */
#include <sys/byteorder.h>

#include <net/buf.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/hci.h>
#include <bluetooth/buf.h>
#include <bluetooth/hci_raw.h>

LOG_MODULE_REGISTER(app);

/*** Start of code copied from the HCI UART Zephyr sample. */

static const struct device *hci_uart_dev;
/* HCI BLE thread data. */
static struct k_thread hci_ble_thread_data;
static K_THREAD_STACK_DEFINE(hci_ble_thread_stack, CONFIG_BT_HCI_TX_STACK_SIZE);
/* HCI BLE TX thread data. */
static struct k_thread tx_thread_data;
static K_THREAD_STACK_DEFINE(tx_thread_stack, CONFIG_BT_HCI_TX_STACK_SIZE);
static K_FIFO_DEFINE(tx_queue);

/* RX in terms of bluetooth communication */
static K_FIFO_DEFINE(uart_tx_queue);

#define H4_CMD 0x01
#define H4_ACL 0x02
#define H4_SCO 0x03
#define H4_EVT 0x04

/* Receiver states. */
#define ST_IDLE 0	/* Waiting for packet type. */
#define ST_HDR 1	/* Receiving packet header. */
#define ST_PAYLOAD 2	/* Receiving packet payload. */
#define ST_DISCARD 3	/* Dropping packet. */

/* Length of a discard/flush buffer.
 * This is sized to align with a BLE HCI packet:
 * 1 byte H:4 header + 32 bytes ACL/event data
 * Bigger values might overflow the stack since this is declared as a local
 * variable, smaller ones will force the caller to call into discard more
 * often.
 */
#define H4_DISCARD_LEN 33

static int h4_read(const struct device *uart, uint8_t *buf, size_t len)
{
	int rx = uart_fifo_read(uart, buf, len);

	LOG_DBG("read %d req %d", rx, len);

	return rx;
}

static bool valid_type(uint8_t type)
{
	return (type == H4_CMD) | (type == H4_ACL);
}

/* Function assumes that type is validated and only CMD or ACL will be used. */
static uint32_t get_len(const uint8_t *hdr_buf, uint8_t type)
{
	return (type == BT_BUF_CMD) ?
		((const struct bt_hci_cmd_hdr *)hdr_buf)->param_len :
		sys_le16_to_cpu(((const struct bt_hci_acl_hdr *)hdr_buf)->len);
}

/* Function assumes that type is validated and only CMD or ACL will be used. */
static int hdr_len(uint8_t type)
{
	return (type == H4_CMD) ?
		sizeof(struct bt_hci_cmd_hdr) : sizeof(struct bt_hci_acl_hdr);
}

static void rx_isr(void)
{
	static struct net_buf *buf;
	static int remaining;
	static uint8_t state;
	static uint8_t type;
	static uint8_t hdr_buf[MAX(sizeof(struct bt_hci_cmd_hdr),
			sizeof(struct bt_hci_acl_hdr))];
	int read;

	do {
		switch (state) {
		case ST_IDLE:
			/* Get packet type */
			read = h4_read(hci_uart_dev, &type, sizeof(type));
			/* since we read in loop until no data is in the fifo,
			 * it is possible that read = 0.
			 */
			if (read) {
				if (valid_type(type)) {
					/* Get expected header size and switch
					 * to receiving header.
					 */
					remaining = hdr_len(type);
					state = ST_HDR;
				} else {
					LOG_WRN("Unknown header %d", type);
				}
			}
			break;
		case ST_HDR:
			read = h4_read(hci_uart_dev,
				       &hdr_buf[hdr_len(type) - remaining],
				       remaining);
			remaining -= read;
			if (remaining == 0) {
				/* Header received. Allocate buffer and get
				 * payload length. If allocation fails leave
				 * interrupt. On failed allocation state machine
				 * is reset.
				 */
				buf = bt_buf_get_tx(BT_BUF_H4, K_NO_WAIT,
						    &type, sizeof(type));
				if (!buf) {
					state = ST_IDLE;
					return;
				}

				remaining = get_len(hdr_buf, type);

				net_buf_add_mem(buf, hdr_buf, hdr_len(type));
				if (remaining > net_buf_tailroom(buf)) {
					LOG_ERR("Not enough space in buffer");
					net_buf_unref(buf);
					state = ST_DISCARD;
				} else {
					state = ST_PAYLOAD;
				}

			}
			break;
		case ST_PAYLOAD:
			read = h4_read(hci_uart_dev, net_buf_tail(buf),
				       remaining);
			buf->len += read;
			remaining -= read;
			if (remaining == 0) {
				/* Packet received */
				LOG_DBG("putting RX packet in queue.");
				net_buf_put(&tx_queue, buf);
				state = ST_IDLE;
			}
			break;
		case ST_DISCARD:
		{
			uint8_t discard[H4_DISCARD_LEN];
			size_t to_read = MIN(remaining, sizeof(discard));

			read = h4_read(hci_uart_dev, discard, to_read);
			remaining -= read;
			if (remaining == 0) {
				state = ST_IDLE;
			}

			break;

		}
		default:
			read = 0;
			__ASSERT_NO_MSG(0);
			break;

		}
	} while (read);
}

static void tx_isr(void)
{
	static struct net_buf *buf;
	int len;

	if (!buf) {
		buf = net_buf_get(&uart_tx_queue, K_NO_WAIT);
		if (!buf) {
			uart_irq_tx_disable(hci_uart_dev);
			return;
		}
	}

	len = uart_fifo_fill(hci_uart_dev, buf->data, buf->len);
	net_buf_pull(buf, len);
	if (!buf->len) {
		net_buf_unref(buf);
		buf = NULL;
	}
}

static void bt_uart_isr(const struct device *unused, void *user_data)
{
	ARG_UNUSED(unused);
	ARG_UNUSED(user_data);

	if (!(uart_irq_rx_ready(hci_uart_dev) ||
	      uart_irq_tx_ready(hci_uart_dev))) {
		LOG_DBG("spurious interrupt");
	}

	if (uart_irq_tx_ready(hci_uart_dev)) {
		tx_isr();
	}

	if (uart_irq_rx_ready(hci_uart_dev)) {
		rx_isr();
	}
}

static void tx_thread(void *p1, void *p2, void *p3)
{
	while (1) {
		struct net_buf *buf;
		int err;

		/* Wait until a buffer is available */
		buf = net_buf_get(&tx_queue, K_FOREVER);
		/* Pass buffer to the stack */
		err = bt_send(buf);
		if (err) {
			LOG_ERR("Unable to send (err %d)", err);
			net_buf_unref(buf);
		}

		/* Give other threads a chance to run if tx_queue keeps getting
		 * new data all the time.
		 */
		k_yield();
	}
}

static int h4_send(struct net_buf *buf)
{
	LOG_DBG("buf %p type %u len %u", buf, bt_buf_get_type(buf),
		    buf->len);

	net_buf_put(&uart_tx_queue, buf);
	uart_irq_tx_enable(hci_uart_dev);

	return 0;
}

#if defined(CONFIG_BT_CTLR_ASSERT_HANDLER)
void bt_ctlr_assert_handle(char *file, uint32_t line)
{
	uint32_t len = 0U, pos = 0U;

	/* Disable interrupts, this is unrecoverable */
	(void)irq_lock();

	uart_irq_rx_disable(hci_uart_dev);
	uart_irq_tx_disable(hci_uart_dev);

	if (file) {
		while (file[len] != '\0') {
			if (file[len] == '/') {
				pos = len + 1;
			}
			len++;
		}
		file += pos;
		len -= pos;
	}

	uart_poll_out(hci_uart_dev, H4_EVT);
	/* Vendor-Specific debug event */
	uart_poll_out(hci_uart_dev, 0xff);
	/* 0xAA + strlen + \0 + 32-bit line number */
	uart_poll_out(hci_uart_dev, 1 + len + 1 + 4);
	uart_poll_out(hci_uart_dev, 0xAA);

	if (len) {
		while (*file != '\0') {
			uart_poll_out(hci_uart_dev, *file);
			file++;
		}
		uart_poll_out(hci_uart_dev, 0x00);
	}

	uart_poll_out(hci_uart_dev, line >> 0 & 0xff);
	uart_poll_out(hci_uart_dev, line >> 8 & 0xff);
	uart_poll_out(hci_uart_dev, line >> 16 & 0xff);
	uart_poll_out(hci_uart_dev, line >> 24 & 0xff);

	while (1) {
	}
}
#endif /* CONFIG_BT_CTLR_ASSERT_HANDLER */

static int hci_uart_init(const struct device *unused)
{
	LOG_DBG("");

	/* Derived from DT's bt-c2h-uart chosen node */
	hci_uart_dev = device_get_binding(CONFIG_BT_CTLR_TO_HOST_UART_DEV_NAME);
	if (!hci_uart_dev) {
		return -EINVAL;
	}

	uart_irq_rx_disable(hci_uart_dev);
	uart_irq_tx_disable(hci_uart_dev);

	uart_irq_callback_set(hci_uart_dev, bt_uart_isr);

	uart_irq_rx_enable(hci_uart_dev);

	return 0;
}

/*** End of code copied from the HCI UART Zephyr sample. */

/* Main thread of HCI UART sample, represents the main() function of the HCI UART sample. */
static void hci_ble_thread(void *p1, void *p2, void *p3)
{
	/* Copied from the HCI UART example. */
	/* incoming events and data from the controller */
	static K_FIFO_DEFINE(rx_queue);
	int err;

	hci_uart_init(NULL);

#ifdef CONFIG_UART_LINE_CTRL
	uint32_t dtr = 0U;

	while (true) {
	uart_line_ctrl_get(hci_uart_dev, UART_LINE_CTRL_DTR, &dtr);
	if (dtr) {
		break;
	}
	/* Give CPU resources to low priority threads. */
	k_sleep(K_MSEC(100));
	}

	/* Data Carrier Detect Modem - mark connection as established. */
	(void)uart_line_ctrl_set(hci_uart_dev, UART_LINE_CTRL_DCD, 1);
	/* Data Set Ready - the NCP SoC is ready to communicate. */
	(void)uart_line_ctrl_set(hci_uart_dev, UART_LINE_CTRL_DSR, 1);

	k_busy_wait(1000000);
#endif /* CONFIG_UART_LINE_CTRL */

	LOG_DBG("Start");
	__ASSERT(hci_uart_dev, "UART device is NULL");

	/* Enable the raw interface, this will in turn open the HCI driver */
	bt_enable_raw(&rx_queue);

	if (IS_ENABLED(CONFIG_BT_WAIT_NOP)) {
		/* Issue a Command Complete with NOP */
		int i;

		const struct {
			const uint8_t h4;
			const struct bt_hci_evt_hdr hdr;
			const struct bt_hci_evt_cmd_complete cc;
		} __packed cc_evt = {
			.h4 = H4_EVT,
			.hdr = {
				.evt = BT_HCI_EVT_CMD_COMPLETE,
				.len = sizeof(struct bt_hci_evt_cmd_complete),
			},
			.cc = {
				.ncmd = 1,
				.opcode = sys_cpu_to_le16(BT_OP_NOP),
			},
		};

		for (i = 0; i < sizeof(cc_evt); i++) {
			uart_poll_out(hci_uart_dev,
				      *(((const uint8_t *)&cc_evt)+i));
		}
	}

	/* Spawn the TX thread and start feeding commands and data to the
	 * controller
	 */
	k_thread_create(&tx_thread_data, tx_thread_stack,
			K_THREAD_STACK_SIZEOF(tx_thread_stack), tx_thread,
			NULL, NULL, NULL, K_PRIO_COOP(7), 0, K_NO_WAIT);
	k_thread_name_set(&tx_thread_data, "HCI uart TX");

	while (1) {
		struct net_buf *buf;

		buf = net_buf_get(&rx_queue, K_FOREVER);
		err = h4_send(buf);
		if (err) {
			LOG_ERR("Failed to send");
		}
	}
}

int main(void)
{
	LOG_INF("Starting Zigbee Network Co-processor sample");

#ifdef CONFIG_USB
	/* Enable USB device. */
	int ret = usb_enable(NULL);

	if (ret != 0) {
		return ret;
	}

	/* Create BLE HCI thread. */
	k_thread_create(&hci_ble_thread_data, hci_ble_thread_stack,
			K_THREAD_STACK_SIZEOF(hci_ble_thread_stack), hci_ble_thread,
			NULL, NULL, NULL, K_PRIO_COOP(7), 0, K_NO_WAIT);
	k_thread_name_set(&hci_ble_thread_data, "HCI  BLE main thread");

#ifdef CONFIG_UART_LINE_CTRL
	const struct device *uart_dev;
	uint32_t dtr = 0U;

	uart_dev = device_get_binding(CONFIG_ZIGBEE_UART_DEVICE_NAME);
	if (uart_dev == NULL) {
		LOG_ERR("Error during serial initialization");
		return -EIO;
	}

	while (true) {
		uart_line_ctrl_get(uart_dev, UART_LINE_CTRL_DTR, &dtr);
		if (dtr) {
			break;
		}
		/* Give CPU resources to low priority threads. */
		k_sleep(K_MSEC(100));
	}

	/* Data Carrier Detect Modem - mark connection as established. */
	(void)uart_line_ctrl_set(uart_dev, UART_LINE_CTRL_DCD, 1);
	/* Data Set Ready - the NCP SoC is ready to communicate. */
	(void)uart_line_ctrl_set(uart_dev, UART_LINE_CTRL_DSR, 1);

	k_busy_wait(1000000);

#endif /* CONFIG_UART_LINE_CTRL */

	/* Wait 1 sec for the host to do all settings */
	k_sleep(K_SECONDS(1));

#endif /* CONFIG_USB */

	zb_osif_ncp_set_nvram_filter();

	/* Start Zigbee default thread */
	zigbee_enable();

	LOG_INF("Zigbee Network Co-processor sample started");

	return 0;
}
