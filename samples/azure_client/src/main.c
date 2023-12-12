/*
 * Copyright (c) 2020-2023 Nordic Semiconductor ASA
 * Copyright (c) 2023 Moran Rozenszajn
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/reboot.h>
#include <zephyr/dfu/mcuboot.h>
#include <net/azure_iot_hub.h>
#include <net/azure_iot_hub_dps.h>
#include <zephyr/pm/device.h>
#include <zephyr/pm/device_runtime.h>
#include <zephyr/logging/log.h>
#include <zephyr/device.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/devicetree.h>

#include <cJSON.h>
#include <cJSON_os.h>

LOG_MODULE_REGISTER(MAIN);

/* Interval [s] between sending events to the IoT hub. The value can be changed
 * by setting a new desired value for property 'telemetryInterval' in the
 * device twin document.
 */
#define EVENT_INTERVAL 20
#define RECV_BUF_SIZE 1024
#define APP_WORK_Q_STACK_SIZE KB(8)

static const struct device *modem = DEVICE_DT_GET(DT_ALIAS(modem));

static struct method_data
{
	struct k_work work;
	char request_id[8];
	char name[32];
	char payload[200];
} method_data;
static struct k_work twin_report_work;
static struct k_work_delayable send_event_work;
static struct k_work_delayable reboot_work;

static char recv_buf[RECV_BUF_SIZE];
static void direct_method_handler(struct k_work *work);
static K_SEM_DEFINE(recv_buf_sem, 1, 1);
static atomic_t event_interval = EVENT_INTERVAL;

// Must be supplied by the user in the CMakeLists.txt file
static uint8_t azure_ca_cert[] = {
#include "azure_ca_cert.inc"
};

// Must be supplied by the user in the CMakeLists.txt file
static uint8_t azure_client_cert[] = {
#include "azure_client_cert.inc"
};

// Must be supplied by the user in the CMakeLists.txt file
static uint8_t azure_client_key[] = {
#include "azure_client_key.inc"
};

/* A work queue is created to execute potentially blocking calls from.
 * This is done to avoid blocking for example the system work queue for extended
 * periods of time.
 */
static K_THREAD_STACK_DEFINE(application_stack_area, APP_WORK_Q_STACK_SIZE);
static struct k_work_q application_work_q;

/* Returns a positive integer if the new interval can be parsed, otherwise -1 */
static int event_interval_get(char *buf)
{
	struct cJSON *root_obj, *desired_obj, *event_interval_obj;
	int new_interval = -1;

	root_obj = cJSON_Parse(buf);
	if (root_obj == NULL)
	{
		LOG_ERR("Could not parse properties object");
		return -1;
	}

	/* If the incoming buffer is a notification from the cloud about changes
	 * made to the device twin's "desired" properties, the root object will
	 * only contain the newly changed properties, and can be treated as if
	 * it is the "desired" object.
	 * If the incoming is the response to a request to receive the device
	 * twin, it will contain a "desired" object and a "reported" object,
	 * and we need to access that object instead of the root.
	 */
	desired_obj = cJSON_GetObjectItem(root_obj, "desired");
	if (desired_obj == NULL)
	{
		desired_obj = root_obj;
	}

	/* Update only recognized properties. */
	event_interval_obj = cJSON_GetObjectItem(desired_obj,
											 "telemetryInterval");
	if (event_interval_obj == NULL)
	{
		LOG_INF("No 'telemetryInterval' object in the device twin");
		goto clean_exit;
	}

	if (cJSON_IsString(event_interval_obj))
	{
		new_interval = atoi(event_interval_obj->valuestring);
	}
	else if (cJSON_IsNumber(event_interval_obj))
	{
		new_interval = event_interval_obj->valueint;
	}
	else
	{
		LOG_WRN("Invalid telemetry interval format received");
		goto clean_exit;
	}

clean_exit:
	cJSON_Delete(root_obj);
	k_sem_give(&recv_buf_sem);

	return new_interval;
}

static void event_interval_apply(int interval)
{
	if (interval <= 0)
	{
		return;
	}

	atomic_set(&event_interval, interval);
	k_work_reschedule_for_queue(&application_work_q, &send_event_work, K_NO_WAIT);
}

static int certificates_provision(void)
{
	int err;

	err = tls_credential_add(CONFIG_MQTT_HELPER_SEC_TAG,
							 TLS_CREDENTIAL_CA_CERTIFICATE,
							 azure_ca_cert,
							 sizeof(azure_ca_cert));
	if (err < 0)
	{
		LOG_ERR("Failed to register CA certificate: %d", err);
		return err;
	}

	err = tls_credential_add(CONFIG_MQTT_HELPER_SEC_TAG,
							 TLS_CREDENTIAL_SERVER_CERTIFICATE,
							 azure_client_cert,
							 sizeof(azure_client_cert));
	if (err < 0)
	{
		LOG_ERR("Failed to register client certificate: %d", err);
		return err;
	}

	err = tls_credential_add(CONFIG_MQTT_HELPER_SEC_TAG,
							 TLS_CREDENTIAL_PRIVATE_KEY,
							 azure_client_key,
							 sizeof(azure_client_key));
	if (err < 0)
	{
		LOG_ERR("Failed to register private key: %d", err);
		return err;
	}

	return 0;
}

static void on_evt_twin_desired(char *buf, size_t len)
{
	if (k_sem_take(&recv_buf_sem, K_NO_WAIT) == 0)
	{
		if (len > sizeof(recv_buf) - 1)
		{
			LOG_ERR("Incoming data too big for buffer");
			return;
		}

		memcpy(recv_buf, buf, len);
		recv_buf[len] = '\0';
		k_work_submit_to_queue(&application_work_q, &twin_report_work);
	}
	else
	{
		LOG_WRN("Recv buffer is busy, data was not copied");
	}
}

static void on_evt_direct_method(struct azure_iot_hub_method *method)
{
	size_t request_id_len = MIN(sizeof(method_data.request_id) - 1, method->request_id.size);
	size_t name_len = MIN(sizeof(method_data.name) - 1, method->name.size);

	LOG_INF("Method name: %.*s", method->name.size, method->name.ptr);
	LOG_INF("Payload: %.*s", method->payload.size, method->payload.ptr);

	memcpy(method_data.request_id, method->request_id.ptr, request_id_len);

	method_data.request_id[request_id_len] = '\0';

	memcpy(method_data.name, method->name.ptr, name_len);
	method_data.name[name_len] = '\0';

	snprintk(method_data.payload, sizeof(method_data.payload),
			 "%.*s", method->payload.size, method->payload.ptr);

	k_work_submit_to_queue(&application_work_q, &method_data.work);
}

static void reboot_work_fn(struct k_work *work)
{
	ARG_UNUSED(work);

	sys_reboot(SYS_REBOOT_COLD);
}

static void azure_event_handler(struct azure_iot_hub_evt *const evt)
{
	switch (evt->type)
	{
	case AZURE_IOT_HUB_EVT_CONNECTING:
		LOG_INF("AZURE_IOT_HUB_EVT_CONNECTING");
		break;
	case AZURE_IOT_HUB_EVT_CONNECTED:
		LOG_INF("AZURE_IOT_HUB_EVT_CONNECTED");
		break;
	case AZURE_IOT_HUB_EVT_CONNECTION_FAILED:
		LOG_INF("AZURE_IOT_HUB_EVT_CONNECTION_FAILED");
		LOG_INF("Error code received from IoT Hub: %d",
				evt->data.err);
		break;
	case AZURE_IOT_HUB_EVT_DISCONNECTED:
		LOG_INF("AZURE_IOT_HUB_EVT_DISCONNECTED");
		break;
	case AZURE_IOT_HUB_EVT_READY:
		LOG_INF("AZURE_IOT_HUB_EVT_READY");

		/* All initializations and cloud connection were successful, now mark
		 * image as working so that we will not revert upon reboot.
		 */
#if defined(CONFIG_BOOTLOADER_MCUBOOT)
		boot_write_img_confirmed();
#endif

		/* The AZURE_IOT_HUB_EVT_READY event indicates that the
		 * IoT hub connection is established and interaction with the
		 * cloud can begin.
		 *
		 * The below work submission will cause send_event() to be
		 * call after 3 seconds.
		 */
		k_work_reschedule_for_queue(&application_work_q,
									&send_event_work, K_NO_WAIT);
		break;
	case AZURE_IOT_HUB_EVT_DATA_RECEIVED:
		LOG_INF("AZURE_IOT_HUB_EVT_DATA_RECEIVED");
		LOG_INF("Received payload: %.*s",
				evt->data.msg.payload.size, evt->data.msg.payload.ptr);
		break;
	case AZURE_IOT_HUB_EVT_TWIN_RECEIVED:
		LOG_INF("AZURE_IOT_HUB_EVT_TWIN_RECEIVED");
		event_interval_apply(event_interval_get(evt->data.msg.payload.ptr));
		break;
	case AZURE_IOT_HUB_EVT_TWIN_DESIRED_RECEIVED:
		LOG_INF("AZURE_IOT_HUB_EVT_TWIN_DESIRED_RECEIVED");
		on_evt_twin_desired(evt->data.msg.payload.ptr, evt->data.msg.payload.size);
		break;
	case AZURE_IOT_HUB_EVT_DIRECT_METHOD:
		LOG_INF("AZURE_IOT_HUB_EVT_DIRECT_METHOD");
		on_evt_direct_method(&evt->data.method);
		break;
	case AZURE_IOT_HUB_EVT_TWIN_RESULT_SUCCESS:
		LOG_INF("AZURE_IOT_HUB_EVT_TWIN_RESULT_SUCCESS, ID: %.*s",
				evt->data.result.request_id.size, evt->data.result.request_id.ptr);
		break;
	case AZURE_IOT_HUB_EVT_TWIN_RESULT_FAIL:
		LOG_INF("AZURE_IOT_HUB_EVT_TWIN_RESULT_FAIL, ID %.*s, status %d",
				evt->data.result.request_id.size,
				evt->data.result.request_id.ptr,
				evt->data.result.status);
		break;
	case AZURE_IOT_HUB_EVT_PUBACK:
		LOG_INF("AZURE_IOT_HUB_EVT_PUBACK");
		break;
	case AZURE_IOT_HUB_EVT_FOTA_START:
		LOG_INF("AZURE_IOT_HUB_EVT_FOTA_START");
		break;
	case AZURE_IOT_HUB_EVT_FOTA_DONE:
		LOG_INF("AZURE_IOT_HUB_EVT_FOTA_DONE");
		LOG_INF("The device will reboot in 5 seconds to apply update");
		k_work_schedule(&reboot_work, K_SECONDS(5));
		break;
	case AZURE_IOT_HUB_EVT_FOTA_ERASE_PENDING:
		LOG_INF("AZURE_IOT_HUB_EVT_FOTA_ERASE_PENDING");
		break;
	case AZURE_IOT_HUB_EVT_FOTA_ERASE_DONE:
		LOG_INF("AZURE_IOT_HUB_EVT_FOTA_ERASE_DONE");
		break;
	case AZURE_IOT_HUB_EVT_FOTA_ERROR:
		LOG_ERR("AZURE_IOT_HUB_EVT_FOTA_ERROR: FOTA failed");
		break;
	case AZURE_IOT_HUB_EVT_ERROR:
		LOG_INF("AZURE_IOT_HUB_EVT_ERROR");
		break;
	default:
		LOG_ERR("Unknown Azure IoT Hub event type: %d", evt->type);
		break;
	}
}

static void send_event(struct k_work *work)
{
	int err;
	static char buf[60];
	ssize_t len;
	struct azure_iot_hub_msg msg = {
		.topic.type = AZURE_IOT_HUB_TOPIC_EVENT,
		.payload.ptr = buf,
		.qos = MQTT_QOS_0_AT_MOST_ONCE,
	};

	len = snprintk(buf, sizeof(buf),
				   "{\"temperature\":%d.%d,\"timestamp\":%d}",
				   25, k_uptime_get_32() % 10, k_uptime_get_32());
	if ((len < 0) || (len > sizeof(buf)))
	{
		LOG_ERR("Failed to populate event buffer");
		goto exit;
	}

	msg.payload.size = len;

	LOG_INF("Sending event:%s", buf);

	err = azure_iot_hub_send(&msg);
	if (err)
	{
		LOG_ERR("Failed to send event");
		goto exit;
	}

	LOG_INF("Event was successfully sent");
exit:
	if (atomic_get(&event_interval) <= 0)
	{
		LOG_ERR("The event reporting stops, interval is set to %ld",
				atomic_get(&event_interval));
		return;
	}

	LOG_INF("Next event will be sent in %ld seconds", event_interval);
	k_work_reschedule_for_queue(&application_work_q, &send_event_work,
								K_SECONDS(event_interval));
}

static void direct_method_handler(struct k_work *work)
{
	int err;
	static char *response = "{\"it\":\"worked\"}";

	/* Status code 200 indicates successful execution of direct method. */
	struct azure_iot_hub_result result = {
		.request_id = {
			.ptr = method_data.request_id,
			.size = strlen(method_data.request_id),
		},
		.status = 200,
		.payload.ptr = response,
		.payload.size = sizeof(response) - 1,
	};

	if (strcmp(method_data.name, "led") != 0)
	{
		LOG_INF("Unknown direct method");
		return;
	}

	err = azure_iot_hub_method_respond(&result);
	if (err)
	{
		LOG_ERR("Failed to send direct method response");
	}
}

static void twin_report_work_fn(struct k_work *work)
{
	int err;
	char buf[100];
	ssize_t len;
	struct azure_iot_hub_msg data = {
		.topic.type = AZURE_IOT_HUB_TOPIC_TWIN_REPORTED,
		.payload.ptr = buf,
		.qos = MQTT_QOS_0_AT_MOST_ONCE,
	};
	int new_interval;

	new_interval = event_interval_get(recv_buf);
	if (new_interval < 0)
	{
		return;
	}

	len = snprintk(buf, sizeof(buf),
				   "{\"telemetryInterval\":%d}", new_interval);
	if (len <= 0)
	{
		LOG_ERR("Failed to create twin report");
		return;
	}

	data.payload.size = len;

	err = azure_iot_hub_send(&data);
	if (err)
	{
		LOG_ERR("Failed to send twin report");
		return;
	}

	/* Note that the new interval value is first applied here, because that
	 * will make the "reported" value in the device twin be in sync with
	 * the reality on the device. Other applications may decide
	 * to apply the desired properties regardless of whether the value is
	 * successfully reported or not.
	 */
	event_interval_apply(new_interval);
	LOG_INF("New telemetry interval has been applied: %d", new_interval);
}

static void work_init(void)
{
	k_work_init(&method_data.work, direct_method_handler);
	k_work_init(&twin_report_work, twin_report_work_fn);
	k_work_init_delayable(&send_event_work, send_event);
	k_work_init_delayable(&reboot_work, reboot_work_fn);
	k_work_queue_start(&application_work_q, application_stack_area,
					   K_THREAD_STACK_SIZEOF(application_stack_area),
					   K_HIGHEST_APPLICATION_THREAD_PRIO, NULL);
}

int main(void)
{
	int err;
	char hostname[128] = CONFIG_AZURE_IOT_HUB_HOSTNAME;
	char device_id[128] = CONFIG_AZURE_IOT_HUB_DEVICE_ID;
	struct azure_iot_hub_config cfg = {
		.device_id = {
			.ptr = device_id,
			.size = strlen(device_id),
		},
		.hostname = {
			.ptr = hostname,
			.size = strlen(hostname),
		},
		.use_dps = true,
	};

	LOG_INF("Azure IoT Hub sample started");
	LOG_INF("Device ID: %s", device_id);
	LOG_INF("Host name: %s", hostname);

	LOG_INF("Bringing network interface up and connecting to the network");

	certificates_provision();

	//  ====================== MODEM UP ======================
	LOG_INF("Powering on modem");
	int ret = pm_device_action_run(modem, PM_DEVICE_ACTION_RESUME);
	if (ret < 0)
	{
		LOG_ERR("Failed to power up modem: %d", ret);
		return -1;
	}

	// =======================================================

	LOG_INF("Connected to network");

	work_init();
	cJSON_Init();

	err = azure_iot_hub_init(azure_event_handler);
	if (err)
	{
		LOG_ERR("Azure IoT Hub could not be initialized, error: %d", err);
		return 0;
	}

	LOG_INF("Azure IoT Hub library initialized");

	err = azure_iot_hub_connect(&cfg);
	if (err < 0)
	{
		LOG_ERR("azure_iot_hub_connect failed: %d", err);
		return 0;
	}

	LOG_INF("Connection request sent to IoT Hub");

	/* After the connection to the IoT hub has been established, the
	 * Azure IoT Hub library will generate events when data is received.
	 * See azure_event_handler() for which actions will be taken on the
	 * various events.
	 */
	return 0;
}
