/*
 * Copyright (c) 2017 Intel Corporation
 * Copyright (c) 2023 Moran Rozenszajn
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
#include <zephyr/net/mqtt.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/conn_mgr_monitor.h>
#include <zephyr/net/conn_mgr_connectivity.h>

LOG_MODULE_REGISTER(MAIN);

#define SERVER_HOST "test.mosquitto.org"
#define APP_CONNECT_TIMEOUT_MS 2000
#define APP_SLEEP_MSECS 500
#define APP_CONNECT_TRIES 10
#define APP_MQTT_BUFFER_SIZE 128
#define MQTT_CLIENTID "zephyr_publisher"

#if CONFIG_BG9X_SSL_MODEM_SECURITY_LEVEL == 2
#define SERVER_PORT 8884
#elif CONFIG_BG9X_SSL_MODEM_SECURITY_LEVEL == 1
#define SERVER_PORT 8883
#else
#define SERVER_PORT 1883
#endif

static const struct device *modem = DEVICE_DT_GET(DT_ALIAS(modem));

static uint8_t rx_buffer[APP_MQTT_BUFFER_SIZE];
static uint8_t tx_buffer[APP_MQTT_BUFFER_SIZE];

/* The mqtt client struct */
static struct mqtt_client client_ctx;

/* MQTT Broker details. */
static struct sockaddr_storage broker;

// uh oh
static struct zsock_pollfd fds[1];
static int nfds;
static bool connected;

static void prepare_fds(struct mqtt_client *client)
{
	if (client->transport.type == MQTT_TRANSPORT_NON_SECURE)
	{
		fds[0].fd = client->transport.tcp.sock;
	}

	fds[0].events = ZSOCK_POLLIN;
	nfds = 1;
}

static void clear_fds(void)
{
	nfds = 0;
}

static int wait(int timeout)
{
	int ret = 0;

	if (nfds > 0)
	{
		ret = zsock_poll(fds, nfds, timeout);
		if (ret < 0)
		{
			LOG_ERR("poll error: %d", errno);
		}
	}

	return ret;
}

void mqtt_evt_handler(struct mqtt_client *const client,
					  const struct mqtt_evt *evt)
{
	int err;

	switch (evt->type)
	{
	case MQTT_EVT_CONNACK:
		if (evt->result != 0)
		{
			LOG_ERR("MQTT connect failed %d", evt->result);
			break;
		}

		connected = true;
		LOG_INF("MQTT client connected!");

		break;

	case MQTT_EVT_DISCONNECT:
		LOG_INF("MQTT client disconnected %d", evt->result);

		connected = false;
		clear_fds();

		break;

	case MQTT_EVT_PUBACK:
		if (evt->result != 0)
		{
			LOG_ERR("MQTT PUBACK error %d", evt->result);
			break;
		}

		LOG_INF("PUBACK packet id: %u", evt->param.puback.message_id);

		break;

	case MQTT_EVT_PUBREC:
		if (evt->result != 0)
		{
			LOG_ERR("MQTT PUBREC error %d", evt->result);
			break;
		}

		LOG_INF("PUBREC packet id: %u", evt->param.pubrec.message_id);

		const struct mqtt_pubrel_param rel_param = {
			.message_id = evt->param.pubrec.message_id};

		err = mqtt_publish_qos2_release(client, &rel_param);
		if (err != 0)
		{
			LOG_ERR("Failed to send MQTT PUBREL: %d", err);
		}

		break;

	case MQTT_EVT_PUBCOMP:
		if (evt->result != 0)
		{
			LOG_ERR("MQTT PUBCOMP error %d", evt->result);
			break;
		}

		LOG_INF("PUBCOMP packet id: %u",
				evt->param.pubcomp.message_id);

		break;

	case MQTT_EVT_PINGRESP:
		LOG_INF("PINGRESP packet");
		break;

	default:
		break;
	}
}

static char *get_mqtt_payload(enum mqtt_qos qos)
{
	static char payload[] = "BG9XSSL:QoSx";

	payload[strlen(payload) - 1] = '0' + qos;

	return payload;
}

static char *get_mqtt_topic(void)
{
	return "bg9xssl";
}

static int msgid = 10;

static int publish(struct mqtt_client *client, enum mqtt_qos qos)
{
	struct mqtt_publish_param param;

	param.message.topic.qos = qos;
	param.message.topic.topic.utf8 = (uint8_t *)get_mqtt_topic();
	param.message.topic.topic.size =
		strlen(param.message.topic.topic.utf8);
	param.message.payload.data = get_mqtt_payload(qos);
	param.message.payload.len =
		strlen(param.message.payload.data);
	param.message_id = msgid++;
	param.dup_flag = 0U;
	param.retain_flag = 0U;

	return mqtt_publish(client, &param);
}

#define RC_STR(rc) ((rc) == 0 ? "OK" : "ERROR")

#define PRINT_RESULT(func, rc) \
	LOG_INF("%s: %d <%s>", (func), rc, RC_STR(rc))

static void broker_init(void)
{
	struct sockaddr_in *broker4 = (struct sockaddr_in *)&broker;
	struct addrinfo *result;

	int ret = getaddrinfo(SERVER_HOST, NULL, NULL, &result);
	if (ret != 0)
	{
		LOG_ERR("ERROR: getaddrinfo failed %d", ret);
		return;
	}

	broker4->sin_family = AF_INET;
	broker4->sin_port = htons(SERVER_PORT);
	broker4->sin_addr.s_addr = ((struct sockaddr_in *)result->ai_addr)->sin_addr.s_addr;

	freeaddrinfo(result);
}

static void client_init(struct mqtt_client *client)
{
	mqtt_client_init(client);

	broker_init();

	/* MQTT client configuration */
	client->broker = &broker;
	client->evt_cb = mqtt_evt_handler;
	client->client_id.utf8 = (uint8_t *)MQTT_CLIENTID;
	client->client_id.size = strlen(MQTT_CLIENTID);
	client->password = NULL;
	client->user_name = NULL;
	client->protocol_version = MQTT_VERSION_3_1_1;

	/* MQTT buffers configuration */
	client->rx_buf = rx_buffer;
	client->rx_buf_size = sizeof(rx_buffer);
	client->tx_buf = tx_buffer;
	client->tx_buf_size = sizeof(tx_buffer);

	/* MQTT transport configuration */
	client->transport.type = MQTT_TRANSPORT_NON_SECURE;
}

/* In this routine we block until the connected variable is 1 */
static int try_to_connect(struct mqtt_client *client)
{
	int rc, i = 0;

	while (i++ < APP_CONNECT_TRIES && !connected)
	{

		client_init(client);

		rc = mqtt_connect(client);
		if (rc != 0)
		{
			PRINT_RESULT("mqtt_connect", rc);
			k_sleep(K_MSEC(APP_SLEEP_MSECS));
			continue;
		}

		prepare_fds(client);

		if (wait(APP_CONNECT_TIMEOUT_MS))
		{
			mqtt_input(client);
		}

		if (!connected)
		{
			mqtt_abort(client);
		}
	}

	if (connected)
	{
		return 0;
	}

	return -EINVAL;
}

static int process_mqtt_and_sleep(struct mqtt_client *client, int timeout)
{
	int64_t remaining = timeout;
	int64_t start_time = k_uptime_get();
	int rc;

	while (remaining > 0 && connected)
	{
		if (wait(remaining))
		{
			rc = mqtt_input(client);
			if (rc != 0)
			{
				PRINT_RESULT("mqtt_input", rc);
				return rc;
			}
		}

		rc = mqtt_live(client);
		if (rc != 0 && rc != -EAGAIN)
		{
			PRINT_RESULT("mqtt_live", rc);
			return rc;
		}
		else if (rc == 0)
		{
			rc = mqtt_input(client);
			if (rc != 0)
			{
				PRINT_RESULT("mqtt_input", rc);
				return rc;
			}
		}

		remaining = timeout + start_time - k_uptime_get();
	}

	return 0;
}

#define SUCCESS_OR_EXIT(rc) \
	{                       \
		if (rc != 0)        \
		{                   \
			return 1;       \
		}                   \
	}
#define SUCCESS_OR_BREAK(rc) \
	{                        \
		if (rc != 0)         \
		{                    \
			break;           \
		}                    \
	}

static int publisher(void)
{
	int i, rc, r = 0;

	LOG_INF("attempting to connect: ");
	rc = try_to_connect(&client_ctx);
	PRINT_RESULT("try_to_connect", rc);
	SUCCESS_OR_EXIT(rc);

	i = 0;
	while (i++ < 10 && connected)
	{
		r = -1;

		rc = mqtt_ping(&client_ctx);
		PRINT_RESULT("mqtt_ping", rc);
		SUCCESS_OR_BREAK(rc);

		rc = process_mqtt_and_sleep(&client_ctx, APP_SLEEP_MSECS);
		SUCCESS_OR_BREAK(rc);

		rc = publish(&client_ctx, MQTT_QOS_0_AT_MOST_ONCE);
		PRINT_RESULT("mqtt_publish QOS 0", rc);
		SUCCESS_OR_BREAK(rc);

		rc = process_mqtt_and_sleep(&client_ctx, APP_SLEEP_MSECS);
		SUCCESS_OR_BREAK(rc);

		rc = publish(&client_ctx, MQTT_QOS_1_AT_LEAST_ONCE);
		PRINT_RESULT("mqtt_publish QOS 1", rc);
		SUCCESS_OR_BREAK(rc);

		rc = process_mqtt_and_sleep(&client_ctx, APP_SLEEP_MSECS);
		SUCCESS_OR_BREAK(rc);

		rc = publish(&client_ctx, MQTT_QOS_2_EXACTLY_ONCE);
		PRINT_RESULT("mqtt_publish QOS 2", rc);
		SUCCESS_OR_BREAK(rc);

		rc = process_mqtt_and_sleep(&client_ctx, APP_SLEEP_MSECS);
		SUCCESS_OR_BREAK(rc);

		r = 0;
	}

	rc = mqtt_disconnect(&client_ctx);
	PRINT_RESULT("mqtt_disconnect", rc);

	return r;
}

static int start_app(void)
{

	int ret;
	uint32_t raised_event;
	const void *info;
	size_t info_len;

	LOG_INF("Powering on modem");
	ret = pm_device_action_run(modem, PM_DEVICE_ACTION_RESUME);
	if (ret < 0)
	{
		LOG_ERR("Failed to power up modem: %d", ret);
		return -1;
	}

	ret = conn_mgr_all_if_up(true);
	if (ret != 0)
	{
		LOG_ERR("Failed to bring up network interface");
		return ret;
	}

	LOG_INF("Waiting for L4 connected");
	ret = net_mgmt_event_wait_on_iface(net_if_get_default(),
									   NET_EVENT_L4_CONNECTED, &raised_event, &info,
									   &info_len, K_SECONDS(120));
	if (ret != 0)
	{
		LOG_ERR("L4 was not connected in time");
		return ret;
	}

	LOG_INF("Publishing");
	ret = publisher();
	PRINT_RESULT("publisher returned", ret);

	LOG_INF("Disconnecting");
	ret = conn_mgr_all_if_disconnect(true);
	if (ret != 0)
	{
		LOG_ERR("Failed to bring up network interface");
		return ret;
	}

	// wait for the network to go down
	k_sleep(K_SECONDS(2));

	ret = conn_mgr_all_if_down(true);
	if (ret != 0)
	{
		LOG_ERR("Failed to bring up network interface");
		return ret;
	}

	LOG_INF("Powering off modem");
	ret = pm_device_action_run(modem, PM_DEVICE_ACTION_SUSPEND);
	if (ret < 0)
	{
		LOG_ERR("Failed to power off modem: %d", ret);
		return -1;
	}

	LOG_INF("Bye!");
	k_sleep(K_SECONDS(3));

	return ret;
}

int main(void)
{

	exit(start_app());
	return 0;
}
