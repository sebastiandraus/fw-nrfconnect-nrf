/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zboss_api.h>
#include <sys/ring_buffer.h>
#include <drivers/uart.h>

#if defined ZB_NRF_TRACE

#include <logging/log.h>

#define ZIGBEE_RX_BUF_LEN 16

LOG_MODULE_REGISTER(zboss, LOG_LEVEL_DBG);

RING_BUF_DECLARE(logger_buf, CONFIG_ZBOSS_TRACE_LOGGER_BUFFER_SIZE);


/* UART device used to print ZBOSS Trace messages. */
static const struct device *uart_dev;
static zb_callback_t char_handler;

static void handle_tx_ready_evt(const struct device *dev)
{
	zb_uint32_t data_len;
	zb_uint32_t data_taken;
	zb_uint8_t *data_ptr;
	int ret_val;

	if (ring_buf_is_empty(&logger_buf)) {
		uart_irq_tx_disable(dev);
		return;
	}

	data_len = ring_buf_get_claim(&logger_buf,
				      &data_ptr,
				      CONFIG_ZBOSS_TRACE_LOGGER_BUFFER_SIZE);

	data_taken = uart_fifo_fill(dev, data_ptr, data_len);

	ret_val = ring_buf_get_finish(&logger_buf, data_taken);

	if (ret_val != 0) {
		LOG_ERR("%u exceeds valid bytes in the logger ring buffer", data_taken);
	}
}

static void uart_rx_bytes(uint8_t *buf, size_t len)
{
	if (char_handler) {
		for (size_t i = 0; i < len; i++) {
			char_handler(buf[i]);
		}
	}
}

static void handle_rx_ready_evt(const struct device *dev)
{
	int recv_len = 0;
	uint8_t buffer[ZIGBEE_RX_BUF_LEN] = {0};

	recv_len = uart_fifo_read(dev, buffer, sizeof(buffer));

	while (recv_len != 0) {
		uart_rx_bytes(buffer, recv_len);

		recv_len = uart_fifo_read(dev, buffer, sizeof(buffer));
	}
}

static void interrupt_handler(const struct device *dev, void *user_data)
{
	while (uart_irq_update(dev) && uart_irq_is_pending(dev)) {
		if (uart_irq_rx_ready(dev)) {
			handle_rx_ready_evt(dev);
		}

		if (uart_irq_tx_ready(dev)) {
			handle_tx_ready_evt(dev);
		}
	}
}

void zb_osif_serial_put_bytes(const zb_uint8_t *buf, zb_short_t len)
{
	zb_uint8_t *buf_dest;
	k_spinlock_key_t key;
	zb_uint32_t allocated = 0;

	if (IS_ENABLED(CONFIG_ZBOSS_TRACE_LOG_LEVEL_OFF)) {
		return;
	}

	/* Disable interrupts when modifing ring buffer so it will not be interrupted. */
	key = k_spin_lock(&logger_buf.lock);

	allocated = ring_buf_put_claim(&logger_buf, &buf_dest, len);

	while (allocated != 0) {
		ZB_MEMCPY(buf_dest, buf, allocated);
		ring_buf_put_finish(&logger_buf, allocated);
		len -= allocated;
		allocated = ring_buf_put_claim(&logger_buf, &buf_dest, len);
	}

	if (len != 0) {
		LOG_DBG("Dropping %u bytes, ring buffer is full", len);
	}

	k_spin_unlock(&logger_buf.lock, key);
}

/* Is called when complete Trace message is put in the ring buffer.
 * Triggers sending buffered data through UART API.
 */
void zb_trace_msg_port_do(void)
{
	if (IS_ENABLED(CONFIG_ZBOSS_TRACE_LOG_LEVEL_OFF)) {
		return;
	}

	uart_irq_tx_enable(uart_dev);
}

void zb_osif_serial_logger_init(void)
{
	if (uart_dev != NULL) {
		return;
	}

	uart_dev = device_get_binding(CONFIG_ZBOSS_TRACE_LOGGER_DEVICE_NAME);
	if (uart_dev == NULL) {
		LOG_ERR("No UART device found to log ZBOSS Traces");
		return;
	}

	uart_irq_callback_set(uart_dev, interrupt_handler);

	/* Enable rx interrupts. */
	uart_irq_rx_enable(uart_dev);
}

void zb_osif_serial_logger_flush(void)
{
	uart_irq_tx_enable(uart_dev);
}

#ifndef CONFIG_ZIGBEE_HAVE_SERIAL
void zb_osif_serial_init(void)
{
	zb_osif_serial_logger_init();
}

void zb_osif_serial_flush(void)
{
	zb_osif_serial_logger_flush();
}

#if defined(CONFIG_ZB_NRF_TRACE_RX_ENABLE)
/* Function set UART RX callback function */
void zb_osif_set_uart_byte_received_cb(zb_callback_t cb)
{
	char_handler = cb;
}
#endif /* CONFIG_ZB_NRF_TRACE_RX_ENABLE */
#endif /* CONFIG_ZIGBEE_HAVE_SERIAL */

#endif /* defined ZB_NRF_TRACE */
