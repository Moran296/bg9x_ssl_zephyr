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
					   "Content-type: application/x-www-form-urlencoded\r\n";

int main(void)
{
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

	buf[x] = '\0';
	LOG_INF("%s", buf);

	zsock_close(sock);

	printk("Sample complete\n");

	return 0;
}
