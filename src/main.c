/*
 * Copyright (c) 2023, Bjarki Arge Andreasen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/device.h>
#include <zephyr/device.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/devicetree.h>
#include <zephyr/kernel.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/dns_resolve.h>
#include <zephyr/pm/device.h>
#include <zephyr/pm/device_runtime.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(MAIN);

static const struct device *modem = DEVICE_DT_GET(DT_ALIAS(modem));
static struct gpio_dt_spec modem_enable = GPIO_DT_SPEC_GET(DT_ALIAS(modem_enable), gpios);

const char REQUEST[] = "GET / HTTP/1.1\r\n"
					   "Host: www.example.com\r\n"
					   "authority: www.example.com\r\n"
					   "accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n"
					   "accept-language: en-US,en;q=0.9\r\n"
					   "cache-control: max-age=0\r\n"
					   "if-modified-since: Thu, 17 Oct 2019 07:18:26 GMT\r\n"
					   "if-none-match: \"3147526947\"\r\n"
					   "referer: https://www.google.com/\r\n"
					   "sec-ch-ua: \"Google Chrome\";v=\"119\", \"Chromium\";v=\"119\", \"Not?A_Brand\";v=\"24\"\r\n"
					   "sec-ch-ua-mobile: ?0\r\n"
					   "sec-ch-ua-platform: \"Windows\"\r\n"
					   "sec-fetch-dest: document\r\n"
					   "sec-fetch-mode: navigate\r\n"
					   "sec-fetch-site: cross-site\r\n"
					   "sec-fetch-user: ?1\r\n"
					   "upgrade-insecure-requests: 1\r\n"
					   "user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36\r\n";

// int test(const struct device *dev)
// {
// 	struct bg9x_ssl_modem_data *data = (struct bg9x_ssl_modem_data *)dev->data;

// 	// TEST DNS?
// 	char ip[17];
// 	if (bg9x_ssl_dns_resolve(data, "example.com", ip) < 0)
// 	{
// 		LOG_ERR("DNS resolve test failed");
// 		return -EINVAL;
// 	}

// 	ip[16] = '\0';
// 	LOG_INF("Resolved DNS to %s", ip);

// 	int ret = bg9x_ssl_open_socket(data, ip, 443);
// 	if (ret < 0)
// 	{
// 		LOG_ERR("Failed to open socket");
// 		return -EINVAL;
// 	}

// 	if (bg9x_ssl_socket_send(data, REQUEST, sizeof(REQUEST)) < 0)
// 	{
// 		LOG_ERR("Failed to send data");
// 		return -EINVAL;
// 	}

// 	static uint8_t recv_buf[1024];

// 	memset(recv_buf, 0, sizeof(recv_buf));
// 	int received = bg9x_ssl_socket_recv(data, recv_buf, sizeof(recv_buf), K_SECONDS(10));
// 	if (received < 0)
// 	{
// 		LOG_ERR("Failed to receive data");
// 		return -EINVAL;
// 	}

// 	received += bg9x_ssl_socket_recv(data, recv_buf + received, sizeof(recv_buf) - received, K_SECONDS(10));
// 	if (received < 0)
// 	{
// 		LOG_ERR("Failed to receive data");
// 		return -EINVAL;
// 	}

// 	received += bg9x_ssl_socket_recv(data, recv_buf + received, sizeof(recv_buf) - received, K_SECONDS(10));
// 	if (received < 0)
// 	{
// 		LOG_ERR("Failed to receive data");
// 		return -EINVAL;
// 	}

// 	LOG_INF("received %d", received);
// 	LOG_INF("%s", (const char *)recv_buf);

// 	return 0;
// }

int main(void)
{
	// uint32_t raised_event;
	// const void *info;
	// size_t info_len;
	int ret;

	printk("Powering on modem enable pin\n");
	gpio_pin_configure_dt(&modem_enable, GPIO_OUTPUT);
	gpio_pin_set_dt(&modem_enable, 1);
	k_sleep(K_SECONDS(3));

	printk("Powering on modem\n");
	ret = pm_device_action_run(modem, PM_DEVICE_ACTION_RESUME);
	if (ret < 0)
	{
		printk("Failed to power up modem: %d\n", ret);
		return -1;
	}

	struct zsock_addrinfo *r;
	int x = getaddrinfo("www.example.com", NULL, NULL, &r);
	if (x < 0)
	{
		LOG_ERR("getaddrinfo: %d", x);
	}

	int sock = zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_TLS_1_0);
	LOG_INF("zsock_socket: %d", sock);

	((struct sockaddr_in *)r->ai_addr)->sin_port = htons(443);
	x = zsock_connect(sock, r->ai_addr, r->ai_addrlen);
	if (x < 0)
	{
		LOG_ERR("zsock_connect: %d", x);
	}

	x = zsock_send(sock, REQUEST, sizeof(REQUEST), 0);
	if (x < 0)
	{
		LOG_ERR("zsock_send: %d", x);
	}

	static char buf[1024];
	x = zsock_recv(sock, buf, sizeof(buf), 0);
	if (x < 0)
	{
		LOG_ERR("zsock_recv: %d", x);
	}

	zsock_close(sock);

	// printk("Restart modem\n");
	// ret = pm_device_action_run(modem, PM_DEVICE_ACTION_SUSPEND);
	// if (ret != 0)
	// {
	// 	printk("Failed to power down modem\n");
	// 	return -1;
	// }

	// pm_device_action_run(modem, PM_DEVICE_ACTION_RESUME);

	printk("Sample complete\n");

	return 0;
}
