#include <zephyr/logging/log.h>
#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/init.h>

#include <zephyr/modem/chat.h>
#include <zephyr/modem/pipe.h>
#include <zephyr/modem/backend/uart.h>

#include <zephyr/pm/device.h>

#include <zephyr/net/net_if.h>
#include <zephyr/net/offloaded_netdev.h>
#include <zephyr/net/net_offload.h>
#include <zephyr/net/socket_offload.h>

LOG_MODULE_REGISTER(modem_quectel_bg9x_ssl, CONFIG_MODEM_LOG_LEVEL);

#define DT_DRV_COMPAT quectel_bg95
#define MODEM_INIT_PRIORITY 99
#define SECURITY_TYPE_SERVER "1"
#define CA_FILE_NAME "ca_file"
#define CLIENT_CERT_FILE_NAME "cl_c_file"
#define CLIENT_KEY_FILE_NAME "cl_k_file"
#define CME_ERR_FILE_DOES_NOT_EXIST "+CME ERROR: 405"

#define SECLEVEL STRINGIFY(CONFIG_BG9X_MODEM_SSL_SECURITY_LEVEL)

struct bg9x_ssl_modem_config
{
    const struct device *uart;
    const struct gpio_dt_spec power_gpio;
    const struct gpio_dt_spec reset_gpio;
    const uint16_t power_pulse_duration_ms;
    const uint16_t startup_time_ms;
    const uint16_t shutdown_time_ms;
    const uint16_t reset_pulse_duration_ms;
};

struct bg9x_ssl_modem_data
{
    // uart backend
    struct modem_pipe *uart_pipe;
    struct modem_backend_uart uart_backend;
    uint8_t uart_backend_receive_buf[512];
    uint8_t uart_backend_transmit_buf[512];

    // chat data
    struct modem_chat chat;
    uint8_t chat_receive_buf[128];
    uint8_t chat_delimiter[1];
    uint8_t chat_filter[1];
    uint8_t *chat_argv[32];

    // state
    bool files_uploaded;
    uint8_t registration_status_gsm;
    uint8_t registration_status_gprs;
    uint8_t registration_status_lte;
    struct k_sem script_sem;

    // certs
    const char *ca_cert;
    const char *client_cert;
    const char *client_key;
    const char *file_to_upload;
    size_t file_to_upload_size;

    // dns
    char *last_resolved_ip[sizeof("255.255.255.255")];
};

static bool modem_cellular_is_registered(struct bg9x_ssl_modem_data *data)
{
    return (data->registration_status_gsm == 1) ||
           (data->registration_status_gsm == 5) ||
           (data->registration_status_gprs == 1) ||
           (data->registration_status_gprs == 5) ||
           (data->registration_status_lte == 1) ||
           (data->registration_status_lte == 5);
}

static void on_cxreg_match_cb(struct modem_chat *chat, char **argv, uint16_t argc,
                              void *user_data)
{
    struct bg9x_ssl_modem_data *data = (struct bg9x_ssl_modem_data *)user_data;
    uint8_t registration_status;
    bool is_registered;

    is_registered = modem_cellular_is_registered(data);

    if (argc == 2)
    {
        registration_status = atoi(argv[1]);
    }
    else if (argc == 3)
    {
        registration_status = atoi(argv[2]);
    }
    else
    {
        return;
    }

    if (strcmp(argv[0], "+CREG: ") == 0)
    {
        data->registration_status_gsm = registration_status;
    }
    else if (strcmp(argv[0], "+CGREG: ") == 0)
    {
        data->registration_status_gprs = registration_status;
    }
    else
    {
        data->registration_status_lte = registration_status;
    }

    if (modem_cellular_is_registered(data))
    {
        LOG_INF("Modem registered");
    }
    else
    {
        LOG_INF("Modem not registered");
    }
}

static void upload_finish_match_cb(struct modem_chat *chat, char **argv, uint16_t argc,
                                   void *user_data)
{
    LOG_INF("upload finish: ");
    for (int i = 0; i < argc; i++)
    {
        LOG_INF("%s", argv[i]);
    }
}

static void upload_file_ready_match_cb(struct modem_chat *chat, char **argv, uint16_t argc,
                                       void *user_data)
{
    struct bg9x_ssl_modem_data *data = (struct bg9x_ssl_modem_data *)user_data;

    const char *buf = data->file_to_upload;
    size_t max_chunk_size = sizeof(data->uart_backend_transmit_buf);
    size_t size_left = data->file_to_upload_size;
    size_t chunk_size;

    if (!buf || size_left == 0)
    {
        LOG_ERR("Invalid file to upload");
        return;
    }

    while (size_left)
    {
        chunk_size = size_left > max_chunk_size ? max_chunk_size : size_left;
        if (modem_pipe_transmit(data->uart_pipe, buf, chunk_size) < 0)
        {
            LOG_ERR("Failed to transmit file");
            return;
        }

        buf += chunk_size;
        size_left -= chunk_size;
        k_sleep(K_MSEC(100)); // Needed?
    }

    LOG_INF("File transmitted");
}

static void resolve_dns_match_cb(struct modem_chat *chat, char **argv, uint16_t argc,
                                 void *user_data)
{
    if (argc == 3)
    {
        struct bg9x_ssl_modem_data *data = (struct bg9x_ssl_modem_data *)user_data;
        memcpy(data->last_resolved_ip, argv[2], 16);
    }
    else
    {
        LOG_ERR("Invalid DNS response");
    }
}

static void resolve_dns_success_match_cb(struct modem_chat *chat, char **argv, uint16_t argc,
                                         void *user_data)
{
    LOG_INF("DNS resolved got success!!");
}

MODEM_CHAT_MATCH_DEFINE(ok_match, "OK", "", NULL);
MODEM_CHAT_MATCH_DEFINE(upload_file_match, "CONNECT", "", upload_file_ready_match_cb);
MODEM_CHAT_MATCH_DEFINE(cpin_match, "+CPIN: READY", "", NULL);

// on successful dns resolve, we get at least 3 response. OK, +QIURC: "dnsgip, <result_code=0>" and +QIURC: "dnsgip", "IP"
MODEM_CHAT_MATCH_DEFINE(resolve_dns_success_match, "+QIURC: \"dnsgip\",0", ",", resolve_dns_success_match_cb);
MODEM_CHAT_MATCH_DEFINE(resolve_dns_ip_match, "+QIURC: \"dnsgip\"", ",", resolve_dns_match_cb);

MODEM_CHAT_MATCH_DEFINE(upload_finish_match, "+QFUPL: ", ",", upload_finish_match_cb);
MODEM_CHAT_MATCH_DEFINE(file_not_exist, CME_ERR_FILE_DOES_NOT_EXIST, "", NULL);

MODEM_CHAT_MATCHES_DEFINE(delete_file_matches, ok_match, file_not_exist);

MODEM_CHAT_MATCHES_DEFINE(abort_matches, MODEM_CHAT_MATCH("ERROR", "", NULL));

MODEM_CHAT_MATCHES_DEFINE(unsol_matches,
                          MODEM_CHAT_MATCH("+CREG: ", ",", on_cxreg_match_cb),
                          MODEM_CHAT_MATCH("+CEREG: ", ",", on_cxreg_match_cb),
                          MODEM_CHAT_MATCH("+CGREG: ", ",", on_cxreg_match_cb));

static void modem_cellular_chat_callback_handler(struct modem_chat *chat,
                                                 enum modem_chat_script_result result,
                                                 void *user_data)
{
    struct bg9x_ssl_modem_data *data = (struct bg9x_ssl_modem_data *)user_data;

    if (result == MODEM_CHAT_SCRIPT_RESULT_SUCCESS)
    {
        LOG_INF("Chat script succeeded");
        k_sem_give(&data->script_sem);
    }
    else
    {
        LOG_INF("Chat script failed");
        k_sem_reset(&data->script_sem);
    }
}

/* ~~~~~~~~~~~~~~~~~~~  UPLOAD FILE CHAT SCRIPT ~~~~~~~~~~~~~~~~~~~~~~ */

// overwritten in write_modem_file
char del_file_cmd[sizeof("AT+QFDEL=\"some_file_name_max\"")];
char upload_file_cmd[sizeof("AT+QFUPL=\"some_file_name_max\",####")];

MODEM_CHAT_SCRIPT_CMDS_DEFINE(bg9x_ssl_upload_file_chat_script_cmds,
                              MODEM_CHAT_SCRIPT_CMD_RESP("ATE0", ok_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP_MULT(del_file_cmd, delete_file_matches),
                              MODEM_CHAT_SCRIPT_CMD_RESP(upload_file_cmd, upload_file_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP("", upload_finish_match), );

MODEM_CHAT_SCRIPT_DEFINE(bg9x_ssl_upload_file_chat_script, bg9x_ssl_upload_file_chat_script_cmds,
                         abort_matches, modem_cellular_chat_callback_handler, 10);

/* ~~~~~~~~~~~~~~~~~~~  DNS RESOLVE CHAT SCRIPT ~~~~~~~~~~~~~~~~~~~~~~ */

// overwritten in modem_dns_resolve functions
char dns_resolve_cmd[sizeof("AT+QIDNSGIP=1,\"some_host_name_url_max#############\"")];

MODEM_CHAT_SCRIPT_CMDS_DEFINE(bg9x_ssl_resolve_dns_chat_script_cmds,
                              MODEM_CHAT_SCRIPT_CMD_RESP(dns_resolve_cmd, ok_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP("", resolve_dns_success_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP("", resolve_dns_ip_match), );

MODEM_CHAT_SCRIPT_DEFINE(bg9x_ssl_resolve_dns_chat_script, bg9x_ssl_resolve_dns_chat_script_cmds,
                         abort_matches, modem_cellular_chat_callback_handler, 60);

/* ~~~~~~~~~~~~~~~~~~~  SSL INIT CHAT SCRIPT ~~~~~~~~~~~~~~~~~~~~~~ */

MODEM_CHAT_SCRIPT_CMDS_DEFINE(bg9x_ssl_init_chat_script_cmds,
                              MODEM_CHAT_SCRIPT_CMD_RESP("ATE0", ok_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP("AT+CREG=1", ok_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP("AT+CGREG=1", ok_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP("AT+CEREG=1", ok_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP("AT+CPIN?", cpin_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP("", ok_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP("AT+QICSGP=1,1,\"" CONFIG_BG9X_MODEM_SSL_APN "\",\"\",\"\",3", ok_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP("AT+CGPADDR=1", ok_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP("AT+QIACT=1", ok_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP("AT+QSSLCFG=\"sslversion\",1,4", ok_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP("AT+QSSLCFG=\"ciphersuite\",1,0xFFFF", ok_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP("AT+QSSLCFG=\"negotiatetime\",1,300", ok_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP("AT+QSSLCFG=\"ignorelocaltime\",1,1", ok_match), // TODO: check if 0 or 1
                              MODEM_CHAT_SCRIPT_CMD_RESP("AT+QSSLCFG=\"seclevel\",1," SECLEVEL, ok_match),
#if CONFIG_BG9X_MODEM_SSL_SECURITY_LEVEL > 0
                              MODEM_CHAT_SCRIPT_CMD_RESP("AT+QSSLCFG=\"cacert\",1,\"" CA_FILE_NAME "\"", ok_match),
#endif
#if CONFIG_BG9X_MODEM_SSL_SECURITY_LEVEL > 1
                              MODEM_CHAT_SCRIPT_CMD_RESP("AT+QSSLCFG=\"clientcert\",1,\"" CLIENT_CERT_FILE_NAME "\"", ok_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP("AT+QSSLCFG=\"clientkey\",1,\"" CLIENT_KEY_FILE_NAME "\"", ok_match),
#endif
);

MODEM_CHAT_SCRIPT_DEFINE(bg9x_ssl_init_chat_script, bg9x_ssl_init_chat_script_cmds,
                         abort_matches, modem_cellular_chat_callback_handler, 10);

static int modem_dns_resolve(struct bg9x_ssl_modem_data *data, const char *host_req, char *ip_resp)
{
    int ret;

    if (!ip_resp || !host_req || strlen(host_req) > sizeof(dns_resolve_cmd))
    {
        LOG_ERR("DNS resolve invalid arguments");
        return -EINVAL;
    }

    snprintk(dns_resolve_cmd, sizeof(dns_resolve_cmd), "AT+QIDNSGIP=1,\"%s\"", host_req);
    ret = modem_chat_script_run(&data->chat, &bg9x_ssl_resolve_dns_chat_script);
    if (ret < 0)
    {
        LOG_ERR("Resolve DNS script failed");
        return ret;
    }

    ret = k_sem_take(&data->script_sem, K_FOREVER);
    if (ret < 0)
    {
        LOG_ERR("Resolve DNS failed");
        return ret;
    }

    if (data->last_resolved_ip[0] == 0)
    {
        LOG_ERR("Failed to resolve DNS");
        return -EIO;
    }

    memcpy(ip_resp, data->last_resolved_ip, 16);
    return 0;
}

static int write_modem_file(struct bg9x_ssl_modem_data *data, const char *name, const char *file, size_t size)
{
    int ret;
    if (!file || size == 0 || !name || strlen(name) > sizeof("some_file_name_max"))
    {
        LOG_ERR("write modem file invalid arguments");
        return -EINVAL;
    }

    snprintk(del_file_cmd, sizeof(del_file_cmd), "AT+QFDEL=\"%s\"", name);
    snprintk(upload_file_cmd, sizeof(upload_file_cmd), "AT+QFUPL=\"%s\",%d", name, size);

    data->file_to_upload = file;
    data->file_to_upload_size = size;

    ret = modem_chat_script_run(&data->chat, &bg9x_ssl_upload_file_chat_script);
    if (ret != 0)
        return ret;

    ret = k_sem_take(&data->script_sem, K_FOREVER);
    return ret;
}

static int bg9x_ssl_modem_write_files(struct bg9x_ssl_modem_data *data)
{
    int ret;

#if CONFIG_BG9X_MODEM_SSL_SECURITY_LEVEL > 0
    ret = write_modem_file(data, CA_FILE_NAME, data->ca_cert, strlen(data->ca_cert));
    if (ret != 0)
    {
        LOG_ERR("Failed to write CA file: %d", ret);
        return ret;
    }
#endif

#if CONFIG_BG9X_MODEM_SSL_SECURITY_LEVEL > 1
    ret = write_modem_file(data, CLIENT_CERT_FILE_NAME, data->client_cert, strlen(data->client_cert));
    if (ret != 0)
    {
        LOG_ERR("Failed to write client cert file: %d", ret);
        return ret;
    }
    ret = write_modem_file(data, CLIENT_KEY_FILE_NAME, data->client_key, strlen(data->client_key));
    if (ret != 0)
    {
        LOG_ERR("Failed to write client key file: %d", ret);
        return ret;
    }
#endif
    LOG_DBG("Files written successfully");

    return 0;
}

static int run_interface_init_script(struct bg9x_ssl_modem_data *data)
{
    int ret;

    ret = modem_chat_script_run(&data->chat, &bg9x_ssl_init_chat_script);
    if (ret != 0)
        return ret;

    return k_sem_take(&data->script_sem, K_FOREVER);
}

int bg9x_ssl_modem_interface_start(struct bg9x_ssl_modem_data *data)
{
    int ret;

    ret = bg9x_ssl_modem_write_files(data);
    if (ret != 0)
        return ret;

    ret = run_interface_init_script(data);

    return ret;
}

int bg9x_ssl_modem_power_on(const struct device *dev)
{
    // power pulse
    struct bg9x_ssl_modem_config *config = (struct bg9x_ssl_modem_config *)dev->config;
    struct bg9x_ssl_modem_data *data = (struct bg9x_ssl_modem_data *)dev->data;

    // modem_pipe_attach(data->uart_pipe, pipe_event_handler, data);
    if (modem_pipe_open(data->uart_pipe) < 0)
    {
        LOG_ERR("Failed to open UART pipe");
        return -EAGAIN;
    }

    if (modem_chat_attach(&data->chat, data->uart_pipe) < 0)
    {
        LOG_ERR("Failed to attach chat to uart");
        return -EAGAIN;
    }

    LOG_INF("Powering on modem");
    LOG_DBG("power_gpio on");
    gpio_pin_set_dt(&config->power_gpio, 1);
    k_sleep(K_MSEC(config->power_pulse_duration_ms));

    LOG_DBG("power_gpio off");
    gpio_pin_set_dt(&config->power_gpio, 0);
    k_sleep(K_MSEC(config->startup_time_ms));

    LOG_DBG("Modem power pulse completed");

    // TEST Configurations
    if (bg9x_ssl_modem_interface_start(data) < 0)
    {
        LOG_ERR("Failed to start modem interface");
        return -EINVAL;
    }

    // TEST DNS?
    char ip[17];
    if (modem_dns_resolve(data, "www.google.com", ip) < 0)
    {
        LOG_ERR("DNS resolve test failed");
        return -EINVAL;
    }

    ip[16] = '\0';
    LOG_INF("Resolved DNS to %s", ip);

    return 0;
}

int bg9x_ssl_modem_power_off(const struct device *dev)
{
    // TODO
    return 0;
}

static int modem_cellular_pm_action(const struct device *dev, enum pm_device_action action)
{
    switch (action)
    {
    case PM_DEVICE_ACTION_RESUME:

        return bg9x_ssl_modem_power_on(dev);
        break;

    case PM_DEVICE_ACTION_SUSPEND:

        return bg9x_ssl_modem_power_off(dev);
        break;

    default:
        return -ENOTSUP;
        break;
    }
}

/* =========================== Device Init ============================================= */
static int bg9x_ssl_init(const struct device *dev)
{
    struct bg9x_ssl_modem_config *config = (struct bg9x_ssl_modem_config *)dev->config;
    struct bg9x_ssl_modem_data *data = (struct bg9x_ssl_modem_data *)dev->data;

    gpio_pin_configure_dt(&config->power_gpio, GPIO_OUTPUT_INACTIVE);
    k_sem_init(&data->script_sem, 0, 1);

    // init uart backend
    const struct modem_backend_uart_config uart_backend_config = {
        .uart = config->uart,
        .receive_buf = data->uart_backend_receive_buf,
        .receive_buf_size = ARRAY_SIZE(data->uart_backend_receive_buf),
        .transmit_buf = data->uart_backend_transmit_buf,
        .transmit_buf_size = ARRAY_SIZE(data->uart_backend_transmit_buf),
    };

    data->uart_pipe = modem_backend_uart_init(&data->uart_backend,
                                              &uart_backend_config);

    // init chat
    const struct modem_chat_config chat_config = {
        .user_data = data,
        .receive_buf = data->chat_receive_buf,
        .receive_buf_size = ARRAY_SIZE(data->chat_receive_buf),
        .delimiter = data->chat_delimiter,
        .delimiter_size = ARRAY_SIZE(data->chat_delimiter),
        .filter = data->chat_filter,
        .filter_size = ARRAY_SIZE(data->chat_filter),
        .argv = data->chat_argv,
        .argv_size = ARRAY_SIZE(data->chat_argv),
        .unsol_matches = unsol_matches,
        .unsol_matches_size = ARRAY_SIZE(unsol_matches),
        .process_timeout = K_MSEC(2),
    };

    modem_chat_init(&data->chat, &chat_config);

    // init ssl files
    data->ca_cert = "I LOVE CAKES";
    data->client_cert = "I LOVE NOODLES";
    data->client_key = "I LOVE BURGERS";

    // init device in suspended state
    pm_device_init_suspended(dev);
    return 0;
}

static struct bg9x_ssl_modem_config modem_config = {
    .uart = DEVICE_DT_GET(DT_INST_BUS(0)),
    .power_gpio = GPIO_DT_SPEC_INST_GET_OR(0, mdm_power_gpios, {}),
    .reset_gpio = GPIO_DT_SPEC_INST_GET_OR(0, mdm_reset_gpios, {}),
    .reset_pulse_duration_ms = 100,
    .power_pulse_duration_ms = 1500,
    .startup_time_ms = 10000,
    .shutdown_time_ms = 5000,
};

static struct bg9x_ssl_modem_data modem_data = {
    .chat_delimiter = {'\r'},
    .chat_filter = {'\n'},
};

PM_DEVICE_DT_INST_DEFINE(0, modem_cellular_pm_action);
DEVICE_DT_INST_DEFINE(0, bg9x_ssl_init, PM_DEVICE_DT_INST_GET(0),
                      &modem_data, &modem_config, POST_KERNEL, MODEM_INIT_PRIORITY, NULL);

/* =========================== Device Init ============================================= */