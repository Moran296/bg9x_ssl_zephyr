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
#include "bg9x_ssl.h"

static const struct device *modem = DEVICE_DT_GET(DT_ALIAS(modem));
static struct gpio_dt_spec modem_enable = GPIO_DT_SPEC_GET(DT_ALIAS(modem_enable), gpios);

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
