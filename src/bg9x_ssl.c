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
#define BUFFER_ACCESS_MODE 0
#define CA_FILE_NAME "ca_file"
#define CLIENT_CERT_FILE_NAME "cl_c_file"
#define CLIENT_KEY_FILE_NAME "cl_k_file"
#define MODEM_CME_ERR_FILE_DOES_NOT_EXIST "+CME ERROR: 405"
#define SECLEVEL STRINGIFY(CONFIG_BG9X_MODEM_SSL_SECURITY_LEVEL)

#if CONFIG_BG9X_MODEM_SSL_SECURITY_LEVEL > 0
uint8_t ca_cert_default[] = {
#include "bg95_ssl_ca_cert.inc"
};
#endif

#if CONFIG_BG9X_MODEM_SSL_SECURITY_LEVEL > 1
uint8_t client_cert_default[] = {
#include "bg95_ssl_client_cert.inc"
};
uint8_t client_key_default[] = {
#include "bg95_ssl_client_key.inc"
};

#endif

enum bg9x_ssl_modem_events
{
    SCRIPT_FINISHED,
    REGISTERED,
    RECV_READY,
};

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
    struct k_sem registration_sem;
    struct k_sem recv_sem;

    // certs
    const uint8_t *ca_cert;
    const uint8_t *client_cert;
    const uint8_t *client_key;

    // buffers
    const uint8_t *data_to_upload;
    size_t data_to_upload_size;

    char *data_to_receive;
    size_t data_to_receive_size;
    size_t pipe_recv_total;

    // dns
    char *last_resolved_ip[sizeof("255.255.255.255")];
};

static int wait_on_modem_event(struct bg9x_ssl_modem_data *data,
                               enum bg9x_ssl_modem_events event,
                               k_timeout_t timeout)
{
    struct k_sem *sem = NULL;

    switch (event)
    {
    case SCRIPT_FINISHED:
        sem = &data->script_sem;
        break;
    case REGISTERED:
        sem = &data->registration_sem;
        break;
    case RECV_READY:
        sem = &data->recv_sem;
        break;

    default:
        return -EINVAL;
    }

    return k_sem_take(sem, timeout);
}

static void notify_modem_event(struct bg9x_ssl_modem_data *data,
                               enum bg9x_ssl_modem_events event,
                               int error)
{
    struct k_sem *sem = NULL;

    switch (event)
    {
    case SCRIPT_FINISHED:
        sem = &data->script_sem;
        break;
    case REGISTERED:
        sem = &data->registration_sem;
        break;
    case RECV_READY:
        sem = &data->recv_sem;
        break;

    default:
        return;
    }

    if (error != 0)
        k_sem_reset(sem);
    else
        k_sem_give(sem);
}

static int modem_run_script_and_wait(struct bg9x_ssl_modem_data *data,
                                     const struct modem_chat_script *script)
{
    int ret;

    ret = modem_chat_script_run(&data->chat, script);
    if (ret != 0)
        return ret;

    // K_FOREVER is not in effect, since timeout is defined in the script
    ret = wait_on_modem_event(data, SCRIPT_FINISHED, K_FOREVER);
    if (ret != 0)
        LOG_ERR("script: %s failed with err %d", script->name, ret);
    else
        LOG_DBG("script: %s finished successfully", script->name);

    return ret;
}

static bool modem_cellular_is_registered(struct bg9x_ssl_modem_data *data)
{
    return (data->registration_status_gsm == 1) ||
           (data->registration_status_gsm == 5) ||
           (data->registration_status_gprs == 1) ||
           (data->registration_status_gprs == 5) ||
           (data->registration_status_lte == 1) ||
           (data->registration_status_lte == 5);
}

static void on_cxreg_match_cb(struct modem_chat *chat, char **argv, uint16_t argc, void *user_data)
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
        notify_modem_event(data, REGISTERED, 0);
        LOG_INF("Modem registered");
    }
    else
    {
        LOG_INF("Modem not registered");
    }
}

static void send_ok_match_cb(struct modem_chat *chat, char **argv, uint16_t argc,
                             void *user_data)
{
    struct bg9x_ssl_modem_data *data = (struct bg9x_ssl_modem_data *)user_data;

    LOG_INF("Send data succeeded");
    notify_modem_event(data, SCRIPT_FINISHED, 0);
}

static void send_fail_match_cb(struct modem_chat *chat, char **argv, uint16_t argc, void *user_data)
{
    struct bg9x_ssl_modem_data *data = (struct bg9x_ssl_modem_data *)user_data;

    LOG_ERR("Send: Connection is established but sending buffer is full");
    notify_modem_event(data, SCRIPT_FINISHED, -EAGAIN);
}

static void upload_finish_match_cb(struct modem_chat *chat, char **argv, uint16_t argc, void *user_data)
{
    struct bg9x_ssl_modem_data *data = (struct bg9x_ssl_modem_data *)user_data;
    if (argc != 3 || atoi(argv[1]) != data->data_to_upload_size)
    {
        LOG_ERR("Upload file data mismatch: argc = %d, argv[1] = %s", argc, argc >= 2 ? argv[1] : "NULL");
    }
    else
    {
        LOG_INF("Upload file finished successfully");
    }
}

static void qsslopen_match_cb(struct modem_chat *chat, char **argv, uint16_t argc, void *user_data)
{
    if (argc != 3)
    {
        LOG_ERR("Invalid socket open response");
        return;
    }

    if (atoi(argv[2]) != 0)
    {
        LOG_ERR("Socket open failed with: %s", argv[2]);
        return;
    }

    LOG_INF("Socket open success");
}

static size_t transmit_data(struct bg9x_ssl_modem_data *data, const uint8_t *buf, size_t len)
{
    size_t max_chunk_size = sizeof(data->uart_backend_transmit_buf);
    size_t size_left = len;
    size_t chunk_size;

    if (!buf || size_left == 0)
    {
        LOG_ERR("Invalid data to upload");
        return 0;
    }

    while (size_left)
    {
        // TODO: This can be made simpler, transmit already checks the chunk size, and returns the number of bytes sent
        chunk_size = size_left > max_chunk_size ? max_chunk_size : size_left;
        if (modem_pipe_transmit(data->uart_pipe, buf, chunk_size) < 0)
        {
            LOG_ERR("Failed to transmit file");
            return len - size_left;
        }

        buf += chunk_size;
        size_left -= chunk_size;
        k_sleep(K_MSEC(100)); // Needed?
    }

    LOG_INF("Data of size %d transmitted", len);
    return len;
}

static void transmit_file_ready_match_cb(struct modem_chat *chat, char **argv, uint16_t argc, void *user_data)
{
    struct bg9x_ssl_modem_data *data = (struct bg9x_ssl_modem_data *)user_data;
    if (transmit_data(data, data->data_to_upload, data->data_to_upload_size) != data->data_to_upload_size)
        LOG_ERR("Failed to transmit data");
}

static void resolve_dns_match_cb(struct modem_chat *chat, char **argv, uint16_t argc,
                                 void *user_data)
{
    struct bg9x_ssl_modem_data *data = (struct bg9x_ssl_modem_data *)user_data;

    if (argc == 3)
    {
        // Remove surrounding quotes
        char *start = argv[2];
        size_t len = strlen(start);

        if (start[0] == '"' && start[len - 1] == '"')
        {
            start[len - 1] = '\0';
            start++;
        }

        memcpy(data->last_resolved_ip, start, strlen(start) + 1);
    }
    else
    {
        LOG_ERR("Invalid DNS response");
    }
}

static void resolve_dns_success_match_cb(struct modem_chat *chat, char **argv, uint16_t argc,
                                         void *user_data)
{
    LOG_INF("DNS resolved got success");
}

static void notify_recv_match_cb(struct modem_chat *chat, char **argv, uint16_t argc,
                                 void *user_data)
{
    struct bg9x_ssl_modem_data *data = (struct bg9x_ssl_modem_data *)user_data;

    LOG_INF("notify unsolicited data recv");
    notify_modem_event(data, RECV_READY, 0);
}

MODEM_CHAT_MATCH_DEFINE(ok_match, "OK", "", NULL);
MODEM_CHAT_MATCH_DEFINE(upload_file_match, "CONNECT", "", transmit_file_ready_match_cb);
MODEM_CHAT_MATCH_DEFINE(cpin_match, "+CPIN: READY", "", NULL);

// on successful dns resolve, we get at least 3 response. OK, +QIURC: "dnsgip, <result_code=0>" and +QIURC: "dnsgip", "IP"
MODEM_CHAT_MATCH_DEFINE(resolve_dns_success_match, "+QIURC: \"dnsgip\",0", ",", resolve_dns_success_match_cb);
MODEM_CHAT_MATCH_DEFINE(resolve_dns_ip_match, "+QIURC: \"dnsgip\"", ",", resolve_dns_match_cb);

MODEM_CHAT_MATCH_DEFINE(upload_finish_match, "+QFUPL: ", ",", upload_finish_match_cb);
MODEM_CHAT_MATCH_DEFINE(file_not_exist, MODEM_CME_ERR_FILE_DOES_NOT_EXIST, "", NULL);

MODEM_CHAT_MATCHES_DEFINE(delete_file_matches, ok_match, file_not_exist);

MODEM_CHAT_MATCHES_DEFINE(abort_matches,
                          MODEM_CHAT_MATCH("ERROR", "", NULL),
                          MODEM_CHAT_MATCH("SEND_FAIL", "", send_fail_match_cb));

MODEM_CHAT_MATCH_DEFINE(qsslopen_match, "+QSSLOPEN: ", ",", qsslopen_match_cb);

// MODEM_CHAT_MATCH_DEFINE(recv_match, "+QSSLRECV:", " ", recv_match_cb);

MODEM_CHAT_MATCHES_DEFINE(unsol_matches,
                          MODEM_CHAT_MATCH("SEND OK", ",", send_ok_match_cb),
                          MODEM_CHAT_MATCH("+QSSLURC: \"recv\"", ",", notify_recv_match_cb),
                          MODEM_CHAT_MATCH("+CREG: ", ",", on_cxreg_match_cb),
                          MODEM_CHAT_MATCH("+CEREG: ", ",", on_cxreg_match_cb),
                          MODEM_CHAT_MATCH("+CGREG: ", ",", on_cxreg_match_cb));

static void modem_cellular_chat_callback_handler(struct modem_chat *chat,
                                                 enum modem_chat_script_result result,
                                                 void *user_data)
{
    struct bg9x_ssl_modem_data *data = (struct bg9x_ssl_modem_data *)user_data;
    int ret = result == MODEM_CHAT_SCRIPT_RESULT_SUCCESS ? 0 : -EIO;
    notify_modem_event(data, SCRIPT_FINISHED, ret);
}

/* ~~~~~~~~~~~~~~~~~~~  UPLOAD FILE CHAT SCRIPT ~~~~~~~~~~~~~~~~~~~~~~ */

// overwritten in write_modem_file
char del_file_cmd_buf[sizeof("AT+QFDEL=\"some_file_name_max\"")];
char upload_file_cmd_buf[sizeof("AT+QFUPL=\"some_file_name_max\",####")];

MODEM_CHAT_SCRIPT_CMDS_DEFINE(bg9x_ssl_upload_file_chat_script_cmds,
                              MODEM_CHAT_SCRIPT_CMD_RESP("ATE0", ok_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP_MULT(del_file_cmd_buf, delete_file_matches),
                              MODEM_CHAT_SCRIPT_CMD_RESP(upload_file_cmd_buf, upload_file_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP("", upload_finish_match), );

MODEM_CHAT_SCRIPT_DEFINE(bg9x_ssl_upload_file_chat_script, bg9x_ssl_upload_file_chat_script_cmds,
                         abort_matches, modem_cellular_chat_callback_handler, 10);

/* ~~~~~~~~~~~~~~~~~~~  DNS RESOLVE CHAT SCRIPT ~~~~~~~~~~~~~~~~~~~~~~ */

// overwritten in modem_dns_resolve functions
char dns_resolve_cmd_buf[sizeof("AT+QIDNSGIP=1,\"some_host_name_url_max#############\"")];

MODEM_CHAT_SCRIPT_CMDS_DEFINE(bg9x_ssl_resolve_dns_chat_script_cmds,
                              MODEM_CHAT_SCRIPT_CMD_RESP(dns_resolve_cmd_buf, ok_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP("", resolve_dns_success_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP("", resolve_dns_ip_match), );

MODEM_CHAT_SCRIPT_DEFINE(bg9x_ssl_resolve_dns_chat_script, bg9x_ssl_resolve_dns_chat_script_cmds,
                         abort_matches, modem_cellular_chat_callback_handler, 60);

/* ~~~~~~~~~~~~~~~~~~~  SSL INIT CHAT SCRIPT ~~~~~~~~~~~~~~~~~~~~~~ */

MODEM_CHAT_SCRIPT_CMDS_DEFINE(bg9x_ssl_init_chat_script_cmds,
                              MODEM_CHAT_SCRIPT_CMD_RESP("ATE0", ok_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP("AT+CPIN?", cpin_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP("", ok_match),
                              // MODEM_CHAT_SCRIPT_CMD_RESP("AT+CREG=1", ok_match), -> not needed?
                              MODEM_CHAT_SCRIPT_CMD_RESP("AT+CGREG=1", ok_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP("AT+CEREG=1", ok_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP("AT+CGREG?", ok_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP("AT+CEREG?", ok_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP("AT+QICSGP=1,1,\"" CONFIG_BG9X_MODEM_SSL_APN "\",\"\",\"\",3", ok_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP("AT+CGPADDR=1", ok_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP("AT+QIACT=1", ok_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP("AT+QSSLCFG=\"sslversion\",1,4", ok_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP("AT+QSSLCFG=\"ciphersuite\",1,0xFFFF", ok_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP("AT+QSSLCFG=\"negotiatetime\",1,300", ok_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP("AT+QSSLCFG=\"ignorelocaltime\",1,0", ok_match),
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

// AT+QSSLOPEN=<pdpctxID>,<sslctxID>,<clientID>,<serveraddr>,<port>[,<access_mode>]
char socket_open_cmd_buf[sizeof("AT+QSSLOPEN:#,##,##\"255.255.255.255\",####,#")];
MODEM_CHAT_SCRIPT_CMDS_DEFINE(bg9x_open_socket_chat_script_cmds,
                              MODEM_CHAT_SCRIPT_CMD_RESP(socket_open_cmd_buf, ok_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP("", qsslopen_match), );

MODEM_CHAT_SCRIPT_DEFINE(bg9x_open_socket_chat_script, bg9x_open_socket_chat_script_cmds,
                         abort_matches, modem_cellular_chat_callback_handler, 10);

// AT+QSSLSEND=<clientID>,<sendlen>
char socket_send_cmd_buf[sizeof("AT+QSSLSEND=##,####")];
MODEM_CHAT_SCRIPT_CMDS_DEFINE(bg9x_socket_send_chat_script_cmds,
                              MODEM_CHAT_SCRIPT_CMD_RESP_NONE(socket_send_cmd_buf, 500));

MODEM_CHAT_SCRIPT_DEFINE(bg9x_socket_send_chat_script, bg9x_socket_send_chat_script_cmds,
                         abort_matches, modem_cellular_chat_callback_handler, 10);

static int socket_send(struct bg9x_ssl_modem_data *data, const uint8_t *buf, size_t len)
{
    int transmitted = 0;
    int ret;
    // TODO: third paramter is socket, we can have more than one (0-11)

    snprintk(socket_send_cmd_buf, sizeof(socket_open_cmd_buf), "AT+QSSLSEND=1,%d", len);

    modem_run_script_and_wait(data, &bg9x_socket_send_chat_script);

    LOG_INF("Sending data of size %d", len);
    transmitted = transmit_data(data, buf, len);
    if (transmitted < len)
    {
        LOG_ERR("Failed to transmit all data. transmitted: %d out of %d", transmitted, len);
        return transmitted;
    }

    // this waits on unsolicited command SEND_OK
    ret = wait_on_modem_event(data, SCRIPT_FINISHED, K_SECONDS(5));
    if (ret < 0)
        return ret;

    return transmitted;
}

// check if buffer ends with "\r\n\r\nOK"
bool is_recv_finished(const char *buf, size_t size)
{
    if (size < 8)
        return false;

    return memcmp(buf + size - 8, "\r\n\r\nOK\r\n", 8) == 0;
}

const char *get_recv_start_pos(const char *buf, size_t size)
{
    if (size < 20)
        return NULL;

    const char *first_occurrence = strstr(buf, "\r\n");
    if (first_occurrence == NULL)
        return NULL;

    const char *second_occurrence = strstr(first_occurrence + 2, "\r\n");
    if (second_occurrence == NULL)
        return NULL;

    return second_occurrence + 2;
}

void pipe_recv_cb(struct modem_pipe *pipe, enum modem_pipe_event event,
                  void *user_data)
{
    struct bg9x_ssl_modem_data *data = (struct bg9x_ssl_modem_data *)user_data;
    int ret;

    switch (event)
    {
    case MODEM_PIPE_EVENT_RECEIVE_READY:

        ret = modem_pipe_receive(pipe,
                                 data->data_to_receive + data->pipe_recv_total,
                                 sizeof(data->uart_backend_receive_buf) - data->pipe_recv_total);

        data->pipe_recv_total += ret;
        LOG_DBG("pipe received %d bytes", ret);

        if (is_recv_finished(data->data_to_receive, data->pipe_recv_total))
            notify_modem_event(data, RECV_READY, 0);

        break;

    default:
        LOG_ERR("unexpected pipe event %d, event", event);
    }
}

static int socket_recv(struct bg9x_ssl_modem_data *data, uint8_t *buf, size_t requested_size, k_timeout_t timeout)
{
    char socket_recv_cmd_buf[sizeof("AT+QSSLRECV=##,####")];
    size_t recv_buf_ability = sizeof(data->uart_backend_receive_buf) - strlen("\r\n+QSSLRECV: ####\r\n") - sizeof("\r\n\r\nOK\r\n");
    size_t max_len = requested_size > recv_buf_ability ? recv_buf_ability : requested_size;

    // This waits on unsolicited commad +QSSLURC: "recv"
    int ret = wait_on_modem_event(data, RECV_READY, timeout);
    if (ret < 0)
        return ret;

    data->data_to_receive = buf;
    data->data_to_receive_size = max_len;
    data->pipe_recv_total = 0;

    modem_chat_release(&data->chat);
    modem_pipe_attach(data->uart_pipe, pipe_recv_cb, data);

    // send the recv at command with the size of the buffer or the max uart receive buffer
    snprintk(socket_recv_cmd_buf, sizeof(socket_recv_cmd_buf), "AT+QSSLRECV=1,%d\r", max_len);
    LOG_INF("Sending %s", socket_recv_cmd_buf);
    ret = modem_pipe_transmit(data->uart_pipe, socket_recv_cmd_buf, strlen(socket_recv_cmd_buf));
    if (ret < 0)
    {
        LOG_ERR("Failed to transmit QSSLRECV: %d", ret);
        goto exit;
    }

    ret = wait_on_modem_event(data, RECV_READY, timeout);
    if (ret < 0)
    {
        LOG_ERR("Failed to receive data");
        goto exit;
    }

    const char *start_pos = get_recv_start_pos(data->data_to_receive, data->pipe_recv_total);
    if (start_pos == NULL)
    {
        LOG_ERR("Failed to parse recv response");
        ret = -EIO;
        goto exit;
    }

    size_t expected_size = atoi(strstr(data->data_to_receive, "+QSSLRECV: ") + strlen("+QSSLRECV: "));

    // extract the response and OK from the buffer
    size_t recv_size = data->pipe_recv_total - (start_pos - data->data_to_receive) - strlen("\r\n\r\nOK\r\n");
    if (recv_size > requested_size)
    {
        LOG_ERR("Received more data than requested");
        ret = -EIO;
        goto exit;
    }

    memmove(data->data_to_receive, start_pos, recv_size);

    ret = recv_size;
    LOG_INF("recv got total %d bytes. expected_size is %d", recv_size, expected_size);

exit:
    modem_pipe_release(data->uart_pipe);
    modem_chat_attach(&data->chat, data->uart_pipe);
    return ret;
}

static int open_socket(struct bg9x_ssl_modem_data *data, const char *ip, uint16_t port)
{
    int ret;
    // TODO: check if socket is already open
    // TODO: third paramter is socket, we can have more than one (0-11)

    snprintk(socket_open_cmd_buf, sizeof(socket_open_cmd_buf), "AT+QSSLOPEN=1,0,1,\"%s\",%d,%d", ip, port, BUFFER_ACCESS_MODE);
    ret = modem_run_script_and_wait(data, &bg9x_open_socket_chat_script);
    if (ret < 0)
        return ret;

    // TODO socket number
    return 1;
}

static int modem_dns_resolve(struct bg9x_ssl_modem_data *data, const char *host_req, char *ip_resp)
{
    int ret;

    if (!ip_resp || !host_req || strlen(host_req) > sizeof(dns_resolve_cmd_buf))
    {
        LOG_ERR("DNS resolve invalid arguments");
        return -EINVAL;
    }

    snprintk(dns_resolve_cmd_buf, sizeof(dns_resolve_cmd_buf), "AT+QIDNSGIP=1,\"%s\"", host_req);

    ret = modem_run_script_and_wait(data, &bg9x_ssl_resolve_dns_chat_script);
    if (ret < 0)
        return ret;

    if (data->last_resolved_ip[0] == 0)
    {
        LOG_ERR("Failed to resolve DNS");
        return -EIO;
    }

    memcpy(ip_resp, data->last_resolved_ip, 16);
    return 0;
}

static int write_modem_file(struct bg9x_ssl_modem_data *data, const char *name, const uint8_t *file, size_t size)
{
    if (size == 0)
    {
        LOG_WRN("%s, file size is 0, skipping file write", name);
        return 0;
    }

    if (!file || !name || strlen(name) > sizeof("some_file_name_max"))
    {
        LOG_ERR("write modem file invalid arguments");
        return -EINVAL;
    }

    snprintk(del_file_cmd_buf, sizeof(del_file_cmd_buf), "AT+QFDEL=\"%s\"", name);
    snprintk(upload_file_cmd_buf, sizeof(upload_file_cmd_buf), "AT+QFUPL=\"%s\",%d", name, size);

    data->data_to_upload = file;
    data->data_to_upload_size = size;

    return modem_run_script_and_wait(data, &bg9x_ssl_upload_file_chat_script);
}

static int bg9x_ssl_modem_write_files(struct bg9x_ssl_modem_data *data)
{
    int ret;
    const uint8_t *file;
    size_t size;

#if CONFIG_BG9X_MODEM_SSL_SECURITY_LEVEL > 0
    file = data->ca_cert ? data->ca_cert : ca_cert_default;
    size = data->ca_cert ? strlen(data->ca_cert) : sizeof(ca_cert_default);

    ret = write_modem_file(data, CA_FILE_NAME, file, size);
    if (ret != 0)
    {
        LOG_ERR("Failed to write CA file: %d", ret);
        return ret;
    }
#endif

#if CONFIG_BG9X_MODEM_SSL_SECURITY_LEVEL > 1
    file = data->client_cert ? data->client_cert : client_cert_default;
    size = data->client_cert ? strlen(data->client_cert) : sizeof(client_cert_default);

    ret = write_modem_file(data, CLIENT_CERT_FILE_NAME, file, size);
    if (ret != 0)
    {
        LOG_ERR("Failed to write client cert file: %d", ret);
        return ret;
    }

    file = data->client_key ? data->client_key : client_key_default;
    size = data->client_key ? strlen(data->client_key) : sizeof(client_key_default);

    ret = write_modem_file(data, CLIENT_KEY_FILE_NAME, file, size);
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

    ret = modem_run_script_and_wait(data, &bg9x_ssl_init_chat_script);
    if (ret != 0)
        return ret;

    ret = wait_on_modem_event(data, REGISTERED, K_SECONDS(20));
    if (ret != 0)
    {
        LOG_ERR("Modem did not register in time");
        return ret;
    }

    return ret;
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
    if (modem_dns_resolve(data, "example.com", ip) < 0)
    {
        LOG_ERR("DNS resolve test failed");
        return -EINVAL;
    }

    ip[16] = '\0';
    LOG_INF("Resolved DNS to %s", ip);

    int sock = open_socket(data, ip, 443);
    if (sock < 0)
    {
        LOG_ERR("Failed to open socket");
        return -EINVAL;
    }

    if (socket_send(data, REQUEST, sizeof(REQUEST) /* - 1*/) < 0)
    {
        LOG_ERR("Failed to send data");
        return -EINVAL;
    }

    static uint8_t recv_buf[1024];

    int received = socket_recv(data, recv_buf, sizeof(recv_buf), K_SECONDS(10));
    if (received < 0)
    {
        LOG_ERR("Failed to receive data");
        return -EINVAL;
    }

    LOG_INF("received %d", received);

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

    data->ca_cert = NULL;     // allows CONFIG_BG9X_MODEM_SSL_CA_CERT to be used
    data->client_cert = NULL; // allows CONFIG_BG9X_MODEM_SSL_CLIENT_CERT to be used
    data->client_key = NULL;  // allows CONFIG_BG9X_MODEM_SSL_CLIENT_KEY to be used

    gpio_pin_configure_dt(&config->power_gpio, GPIO_OUTPUT_INACTIVE);
    k_sem_init(&data->script_sem, 0, 1);
    k_sem_init(&data->registration_sem, 0, 1);
    k_sem_init(&data->recv_sem, 0, 1);

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
                      &modem_data, &modem_config, POST_KERNEL, 99, NULL);

/* =========================== Device Init ============================================= */