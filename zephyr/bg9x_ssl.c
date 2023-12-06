#define _GNU_SOURCE
#include <string.h>
#include <zephyr/logging/log.h>
#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/init.h>

#include <zephyr/modem/chat.h>
#include <zephyr/modem/pipe.h>
#include <zephyr/modem/backend/uart.h>
#include <sockets_internal.h>

#include <zephyr/pm/device.h>

#include <zephyr/net/net_if.h>
#include <zephyr/net/offloaded_netdev.h>
#include <zephyr/net/net_offload.h>
#include <zephyr/net/socket_offload.h>

LOG_MODULE_REGISTER(modem_quectel_bg9x_ssl, CONFIG_MODEM_LOG_LEVEL);

#define DT_DRV_COMPAT quectel_bg95
#define QUECTEL_BUFFER_ACCESS_MODE 0
#define QUECTEL_CME_ERR_FILE_DOES_NOT_EXIST "+CME ERROR: 405"

#define MODEM_MAX_DATA_LENGTH 1024
#define CA_FILE_NAME "ca_file"
#define CLIENT_CERT_FILE_NAME "cl_c_file"
#define CLIENT_KEY_FILE_NAME "cl_k_file"
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

enum bg9x_ssl_modem_socket_state
{
    SSL_STATE_INITIAL = 0,
    SSL_STATE_OPENING = 1,
    SSL_STATE_CONNECTED = 2,
    SSL_STATE_CLOSING = 4,
};

const char *ssl_state_to_string(enum bg9x_ssl_modem_socket_state state)
{
    switch (state)
    {
    case SSL_STATE_INITIAL:
        return "SSL_STATE_INITIAL";
    case SSL_STATE_OPENING:
        return "SSL_STATE_OPENING";
    case SSL_STATE_CONNECTED:
        return "SSL_STATE_CONNECTED";
    case SSL_STATE_CLOSING:
        return "SSL_STATE_CLOSING";
    default:
        return "SSL_STATE_UNKNOWN";
    }
}

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
    // net interface related
    struct net_if *net_iface;
    uint8_t mac_addr[6];

    // uart backend
    struct modem_pipe *uart_pipe;
    struct modem_backend_uart uart_backend;
    uint8_t uart_backend_receive_buf[MODEM_MAX_DATA_LENGTH];
    uint8_t uart_backend_transmit_buf[MODEM_MAX_DATA_LENGTH];

    // chat data
    struct modem_chat chat;
    uint8_t chat_receive_buf[128];
    uint8_t chat_delimiter[1];
    uint8_t chat_filter[1];
    uint8_t *chat_argv[32];

    // reg state
    uint8_t registration_status_gsm;
    uint8_t registration_status_gprs;
    uint8_t registration_status_lte;
    struct k_sem registration_sem;

    // certs
    const uint8_t *ca_cert;
    const uint8_t *client_cert;
    const uint8_t *client_key;

    // error handling
    int last_error;

    // ==== SOCKET RELATED ====
    int fd;
    enum bg9x_ssl_modem_socket_state socket_state;
    bool socket_blocking;
    bool socket_has_data;
    struct k_sem script_sem;
    struct k_sem recv_sem;

    /** data ready poll signal */
    struct k_poll_signal sig_data_ready;

    // buffers
    const uint8_t *data_to_upload;
    size_t data_to_upload_size;

    char *data_to_receive;
    size_t data_to_receive_size;
    size_t pipe_recv_total;

    // dns
    struct zsock_addrinfo *last_resolved_addr_info;
    int resolved_addr_count;
};

extern char *strnstr(const char *haystack, const char *needle, size_t haystack_sz);
static void resolve_dns_match_cb(struct modem_chat *chat, char **argv, uint16_t argc, void *user_data);
static int offload_socket(int family, int type, int proto);
static int bg9x_ssl_close_socket(struct bg9x_ssl_modem_data *data);

static struct bg9x_ssl_modem_data modem_data = {
    .chat_delimiter = {'\r'},
    .chat_filter = {'\n'},
};

static struct bg9x_ssl_modem_config modem_config = {
    .uart = DEVICE_DT_GET(DT_INST_BUS(0)),
    .power_gpio = GPIO_DT_SPEC_INST_GET_OR(0, mdm_power_gpios, {}),
    .reset_gpio = GPIO_DT_SPEC_INST_GET_OR(0, mdm_reset_gpios, {}),
    .reset_pulse_duration_ms = 100,
    .power_pulse_duration_ms = 1500,
    .startup_time_ms = 10000,
    .shutdown_time_ms = 5000,
};

static int try_atoi(const char *s)
{
    int ret;
    char *endptr;

    ret = (int)strtol(s, &endptr, 10);
    if (!endptr || endptr == s)
    {
        return -EINVAL;
    }

    return ret;
}

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
        registration_status = try_atoi(argv[1]);
    }
    else if (argc == 3)
    {
        registration_status = try_atoi(argv[2]);
    }
    else
    {
        return;
    }

    if (registration_status < 0)
    {
        LOG_ERR("Invalid registration status %d", registration_status);
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

static void notify_closed_match_cb(struct modem_chat *chat, char **argv, uint16_t argc,
                                   void *user_data)
{
    struct bg9x_ssl_modem_data *data = (struct bg9x_ssl_modem_data *)user_data;

    LOG_INF("unsolicited: socket closed");
    bg9x_ssl_close_socket(data);
}

static void notify_recv_match_cb(struct modem_chat *chat, char **argv, uint16_t argc,
                                 void *user_data)
{
    struct bg9x_ssl_modem_data *data = (struct bg9x_ssl_modem_data *)user_data;

    LOG_INF("unsolicited: data recv");
    k_poll_signal_raise(&data->sig_data_ready, 0);
    notify_modem_event(data, RECV_READY, 0);
}

MODEM_CHAT_MATCH_DEFINE(ok_match, "OK", "", NULL);
MODEM_CHAT_MATCH_DEFINE(upload_file_match, "CONNECT", "", transmit_file_ready_match_cb);
MODEM_CHAT_MATCH_DEFINE(cpin_match, "+CPIN: READY", "", NULL);

// on successful dns resolve, we get at least 3 response. OK, +QIURC: "dnsgip, <result_code=0>" and +QIURC: "dnsgip", "IP"
MODEM_CHAT_MATCHES_DEFINE(abort_matches,
                          MODEM_CHAT_MATCH("ERROR", "", NULL),
                          MODEM_CHAT_MATCH("SEND FAIL", "", send_fail_match_cb));

MODEM_CHAT_MATCHES_DEFINE(unsol_matches,
                          MODEM_CHAT_MATCH("+QSSLURC: \"recv\"", ",", notify_recv_match_cb),
                          MODEM_CHAT_MATCH("+QSSLURC: \"closed\"", ",", notify_closed_match_cb),
                          MODEM_CHAT_MATCH("+QIURC: \"dnsgip\"", ",", resolve_dns_match_cb),
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

/*
 * =======================================================================
 *                          UPLOAD FILES FUNCTIONALITY
 * =======================================================================
 * This section contains code for uploading files to the modem.
 * It includes writing CA cert, client certificate and key files.
 * ========================================================================
 */

MODEM_CHAT_MATCH_DEFINE(upload_finish_match, "+QFUPL: ", ",", upload_finish_match_cb);
MODEM_CHAT_MATCH_DEFINE(file_not_exist, QUECTEL_CME_ERR_FILE_DOES_NOT_EXIST, "", NULL);
MODEM_CHAT_MATCHES_DEFINE(delete_file_matches, ok_match, file_not_exist);

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

static int bg9x_ssl_write_files(struct bg9x_ssl_modem_data *data)
{

#if CONFIG_BG9X_MODEM_SSL_SECURITY_LEVEL > 0
    int ret;
    size_t size;

    if (data->ca_cert != NULL)
    {
        size = data->ca_cert == ca_cert_default ? sizeof(ca_cert_default) : strlen(data->ca_cert);
        ret = write_modem_file(data, CA_FILE_NAME, data->ca_cert, size);
        if (ret != 0)
        {
            LOG_ERR("Failed to write CA file: %d", ret);
            return ret;
        }

        // nullify so will not reupload next connection
        data->ca_cert = NULL;
    }
#endif

#if CONFIG_BG9X_MODEM_SSL_SECURITY_LEVEL > 1
    if (data->client_cert != NULL)
    {
        size = data->client_cert == client_cert_default ? sizeof(client_cert_default) : strlen(data->client_cert);
        ret = write_modem_file(data, CLIENT_CERT_FILE_NAME, data->client_cert, size);
        if (ret != 0)
        {
            LOG_ERR("Failed to write client cert file: %d", ret);
            return ret;
        }

        // nullify so will not reupload next connection
        data->client_cert = NULL
    }

    if (data->client_key != NULL)
    {
        size = data->client_key == client_key_default ? sizeof(client_key_default) : strlen(data->key_cert);
        ret = write_modem_file(data, CLIENT_KEY_FILE_NAME, data->client_key, size);
        if (ret != 0)
        {
            LOG_ERR("Failed to write client key file: %d", ret);
            return ret;
        }

        // nullify so will not reupload next connection
        data->client_key = NULL;
    }

#endif
    LOG_DBG("Files written successfully");

    return 0;
}

/*
 * =======================================================================
 *                          DNS RESOLVE FUNCTIONALITY
 * =======================================================================
 * This contains code for resolving dns address using AT+QIDNSGIP command.
 *
 * We first send a AT+QIDNSGIP=1,"hostname" request with the host name.
 * We wait for OK, then +QIURC: "dnsgip", <ResultCode>, <address_count>, <ttl>
 * and then for each address for <address_count> we get +QIURC: "dnsgip","<IP_addr>"
 * After we received all addresses and allocated them, we can release the semaphore and
 * return the response.
 *
 * ========================================================================
 */
static struct zsock_addrinfo *generate_zsock_addr(struct bg9x_ssl_modem_data *data, const char *ip_addr)
{
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ip_addr, &(sa.sin_addr));
    if (result != 1)
    {
        LOG_ERR("Invalid IP address");
        return NULL;
    }

    struct zsock_addrinfo *res;
    struct sockaddr_in *addr;

    res = calloc(1, sizeof(struct zsock_addrinfo));
    if (!res)
    {
        return NULL;
    }
    addr = calloc(1, sizeof(struct sockaddr_in));
    if (!addr)
    {
        free(res);
        return NULL;
    }

    addr->sin_family = AF_INET;
    addr->sin_addr = sa.sin_addr;
    addr->sin_port = htons(0);

    res->ai_family = AF_INET;
    res->ai_socktype = SOCK_STREAM;
    res->ai_protocol = IPPROTO_TCP;
    res->ai_addr = (struct sockaddr *)addr;
    res->ai_addrlen = sizeof(struct sockaddr_in);
    res->ai_next = NULL;

    return res;
}

static struct zsock_addrinfo *parse_addr_info(struct bg9x_ssl_modem_data *data, char *arg)
{
    // Remove surrounding quotes
    char *start = arg;
    size_t len = strlen(start);

    if (start[0] == '"' && start[len - 1] == '"')
    {
        start[len - 1] = '\0';
        start++;
    }

    LOG_INF("DNS resolved to %s", start);
    struct zsock_addrinfo *addr = generate_zsock_addr(data, start);
    if (!addr)
    {
        LOG_ERR("Failed to generate zsock addr");
        return NULL;
    }

    return addr;
}

int add_addr_info_to_res(struct bg9x_ssl_modem_data *data, struct zsock_addrinfo *addr)
{
    if (!addr)
        return -1;

    int number_of_addresses = 1;
    if (!data->last_resolved_addr_info)
    {
        data->last_resolved_addr_info = addr;
    }
    else
    {
        struct zsock_addrinfo *ptr = data->last_resolved_addr_info;
        while (ptr->ai_next != NULL)
        {
            ptr = ptr->ai_next;
            number_of_addresses++;
        }

        ptr->ai_next = addr;
    }

    return number_of_addresses;
}

static void resolve_dns_match_cb(struct modem_chat *chat, char **argv, uint16_t argc,
                                 void *user_data)
{
    struct bg9x_ssl_modem_data *data = (struct bg9x_ssl_modem_data *)user_data;

    // +QIURC: "dnsgip","<IP_addr>"
    if (argc == 3)
    {
        struct zsock_addrinfo *addr = parse_addr_info(data, argv[2]);
        if (!addr)
        {
            LOG_ERR("Failed to parse addr info");
            return;
        }

        int parsed_addresses = add_addr_info_to_res(data, addr);
        if (parsed_addresses < 0)
        {
            LOG_ERR("Failure at parsing dns address");
            notify_modem_event(data, SCRIPT_FINISHED, -EINVAL);
        }
        else if (parsed_addresses == data->resolved_addr_count)
        {
            LOG_INF("DNS resolved to %d addresses", parsed_addresses);
            notify_modem_event(data, SCRIPT_FINISHED, 0);
        }
    }
    // +QIURC: "dnsgip",<ResultCode>,<address_count>,<ttl>
    else if (argc == 5)
    {
        LOG_DBG("DNS res code: %s", argv[2]);
        if (strcmp(argv[2], "0") != 0)
        {
            LOG_ERR("DNS resolve failed");
            return;
        }

        int expected_addresses = try_atoi(argv[3]);
        if (expected_addresses < 0)
        {
            LOG_ERR("Invalid DNS address count");
            return;
        }

        data->resolved_addr_count = expected_addresses;
        LOG_INF("DNS resolved to %d addresses", expected_addresses);
    }
    else
    {
        LOG_ERR("Invalid DNS response");
    }
}

MODEM_CHAT_MATCH_DEFINE(resolve_dns_ip_match, "+QIURC: \"dnsgip\"", ",", resolve_dns_match_cb);

// overwritten in modem_dns_resolve functions
char dns_resolve_cmd_buf[sizeof("AT+QIDNSGIP=1,\"some_host_name_url_max#############\"")];
MODEM_CHAT_SCRIPT_CMDS_DEFINE(bg9x_ssl_resolve_dns_chat_script_cmds,
                              MODEM_CHAT_SCRIPT_CMD_RESP(dns_resolve_cmd_buf, ok_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP("", resolve_dns_ip_match), );

MODEM_CHAT_SCRIPT_DEFINE(bg9x_ssl_resolve_dns_chat_script, bg9x_ssl_resolve_dns_chat_script_cmds,
                         abort_matches, modem_cellular_chat_callback_handler, 40);

// This currently only resolves one address into a buffer.
static int bg9x_ssl_dns_resolve(struct bg9x_ssl_modem_data *data, const char *host_req, struct zsock_addrinfo **resp)
{
    int ret;

    if (!resp || !host_req || strlen(host_req) > sizeof(dns_resolve_cmd_buf))
    {
        LOG_ERR("DNS resolve invalid arguments");
        return -EINVAL;
    }

    if (data->last_resolved_addr_info != NULL)
    {
        LOG_ERR("Last DNS records were not deallocated, first run freeaddrinfo with previous result");
        return -EINVAL;
    }

    // create request and run
    snprintk(dns_resolve_cmd_buf, sizeof(dns_resolve_cmd_buf), "AT+QIDNSGIP=1,\"%s\"", host_req);
    ret = modem_run_script_and_wait(data, &bg9x_ssl_resolve_dns_chat_script);
    if (ret < 0)
        return ret;

    // wait for all addresses to be resolved
    bool resolved_all_addresses = wait_on_modem_event(data, SCRIPT_FINISHED, K_SECONDS(20)) == 0;
    if (!resolved_all_addresses)
        LOG_ERR("Could not resolve all addresses");

    if (data->last_resolved_addr_info == NULL)
    {
        LOG_ERR("DNS resolve failed");
        return -EINVAL;
    }

    *resp = data->last_resolved_addr_info;
    return 0;
}

/*
 * =======================================================================
 *                          MODEM CONFIGURE AND REGISTRATION
 * =======================================================================
 * This contains code for configuring the modem and registering to the network.
 * It includes setting up the APN, PDP context, and registering to the network.
 * It also configures the modem to use SSL and the SSL configuration.
 *
 * Currently it only supports using files if the compile time security level
 * allows it (ca cert if seclevel >= 1. client cert and key if seclevel == 2).
 * as long as files are configured here, this should run after the file upload step
 *
 * ========================================================================
 */

/* Configure SSL paramters (should run after upload files script) */
MODEM_CHAT_SCRIPT_CMDS_DEFINE(bg9x_ssl_configure_chat_script_cmds,
                              MODEM_CHAT_SCRIPT_CMD_RESP("ATE0", ok_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP("AT+QSSLCFG=\"sslversion\",1,4", ok_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP("AT+QSSLCFG=\"ciphersuite\",1,0xFFFF", ok_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP("AT+QSSLCFG=\"negotiatetime\",1,300", ok_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP("AT+QSSLCFG=\"ignorelocaltime\",1,1", ok_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP("AT+QSSLCFG=\"seclevel\",1," SECLEVEL, ok_match),
#if CONFIG_BG9X_MODEM_SSL_SECURITY_LEVEL > 0
                              MODEM_CHAT_SCRIPT_CMD_RESP("AT+QSSLCFG=\"cacert\",1,\"" CA_FILE_NAME "\"", ok_match),
#endif
#if CONFIG_BG9X_MODEM_SSL_SECURITY_LEVEL > 1
                              MODEM_CHAT_SCRIPT_CMD_RESP("AT+QSSLCFG=\"clientcert\",1,\"" CLIENT_CERT_FILE_NAME "\"", ok_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP("AT+QSSLCFG=\"clientkey\",1,\"" CLIENT_KEY_FILE_NAME "\"", ok_match),
#endif
);

MODEM_CHAT_SCRIPT_DEFINE(bg9x_ssl_configure_chat_script, bg9x_ssl_configure_chat_script_cmds,
                         abort_matches, modem_cellular_chat_callback_handler, 10);

/* Register to the network and activate ssl context */
MODEM_CHAT_SCRIPT_CMDS_DEFINE(bg9x_ssl_register_chat_script_cmds,
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
                              MODEM_CHAT_SCRIPT_CMD_RESP("AT+QIACT=1", ok_match), );

MODEM_CHAT_SCRIPT_DEFINE(bg9x_ssl_register_chat_script, bg9x_ssl_register_chat_script_cmds,
                         abort_matches, modem_cellular_chat_callback_handler, 150);

static int bg9x_ssl_configure(struct bg9x_ssl_modem_data *data)
{
    int ret;

    ret = bg9x_ssl_write_files(data);
    if (ret != 0)
        return ret;

    return modem_run_script_and_wait(data, &bg9x_ssl_configure_chat_script);
}

static int bg9x_ssl_modem_start(struct bg9x_ssl_modem_data *data)
{
    int ret;

    ret = modem_run_script_and_wait(data, &bg9x_ssl_register_chat_script);
    if (ret != 0)
        return ret;

    ret = wait_on_modem_event(data, REGISTERED, K_SECONDS(20));
    if (ret != 0)
        LOG_ERR("Modem did not register in time");

    return ret;
}

/*
 * =======================================================================
 *                          MODEM SOCKET OPEN
 * =======================================================================
 * This contains code for socket open procedure
 *
 * ========================================================================
 */

static void qsslopen_match_cb(struct modem_chat *chat, char **argv, uint16_t argc, void *user_data)
{
    const int sock_open_success = 0;
    struct bg9x_ssl_modem_data *data = (struct bg9x_ssl_modem_data *)user_data;

    if (argc != 3)
    {
        LOG_ERR("Invalid socket open response");
        return;
    }

    if (try_atoi(argv[2]) != sock_open_success)
    {
        LOG_ERR("Socket open failed with: %s", argv[2]);
        return;
    }

    data->socket_state = SSL_STATE_CONNECTED;
    data->socket_blocking = true;
    LOG_INF("socket open success");
}

MODEM_CHAT_MATCH_DEFINE(qsslopen_match, "+QSSLOPEN: ", ",", qsslopen_match_cb);

// AT+QSSLOPEN=<pdpctxID>,<sslctxID>,<clientID>,<serveraddr>,<port>[,<access_mode>]
char socket_open_cmd_buf[sizeof("AT+QSSLOPEN:#,##,##\"255.255.255.255\",####,#")];
MODEM_CHAT_SCRIPT_CMDS_DEFINE(bg9x_open_socket_chat_script_cmds,
                              MODEM_CHAT_SCRIPT_CMD_RESP(socket_open_cmd_buf, ok_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP("", qsslopen_match), );

MODEM_CHAT_SCRIPT_DEFINE(bg9x_open_socket_chat_script, bg9x_open_socket_chat_script_cmds,
                         abort_matches, modem_cellular_chat_callback_handler, 10);

static int bg9x_ssl_open_socket(struct bg9x_ssl_modem_data *data, const char *ip, uint16_t port)
{
    int ret;
    if (data->socket_state == SSL_STATE_CONNECTED)
    {
        LOG_ERR("Socket already connected");
        return -EISCONN;
    }

    // TODO: third paramter is socket, we can have more than one (0-11)

    snprintk(socket_open_cmd_buf, sizeof(socket_open_cmd_buf), "AT+QSSLOPEN=1,0,1,\"%s\",%d,%d", ip, port, QUECTEL_BUFFER_ACCESS_MODE);
    ret = modem_run_script_and_wait(data, &bg9x_open_socket_chat_script);
    if (ret < 0)
        return ret;

    return data->socket_state == SSL_STATE_CONNECTED ? 0 : -EIO;
}
/*
 * =======================================================================
 *                          MODEM SOCKET CLOSE
 * =======================================================================
 * This contains code for socket close procedure
 *
 * ========================================================================
 */

static void close_socket_chat_callback_handler(struct modem_chat *chat,
                                               enum modem_chat_script_result result,
                                               void *user_data)
{
    struct bg9x_ssl_modem_data *data = (struct bg9x_ssl_modem_data *)user_data;

    LOG_DBG("Socket closed and cleared!");
    data->socket_state = SSL_STATE_INITIAL;
    data->socket_blocking = true;
    data->socket_has_data = false;
    k_poll_signal_reset(&data->sig_data_ready);
    k_sem_reset(&data->recv_sem);
    z_free_fd(data->fd);
    data->fd = -1;
}

MODEM_CHAT_SCRIPT_CMDS_DEFINE(bg9x_close_socket_chat_script_cmds,
                              MODEM_CHAT_SCRIPT_CMD_RESP("AT+QSSLCLOSE=1,0", ok_match), );

MODEM_CHAT_SCRIPT_DEFINE(bg9x_close_socket_chat_script, bg9x_close_socket_chat_script_cmds,
                         abort_matches, close_socket_chat_callback_handler, 5);

static int bg9x_ssl_close_socket(struct bg9x_ssl_modem_data *data)
{
    if (data->socket_state == SSL_STATE_INITIAL)
    {
        LOG_DBG("Socket already closed");
        return 0;
    }

    return modem_chat_script_run(&data->chat, &bg9x_close_socket_chat_script);
}

/*
 * =======================================================================
 *                          MODEM FETCH ERROR
 * =======================================================================
 * This contains code for fetching error descriptions from modem
 *
 * ========================================================================
 */

static void get_error_match_cb(struct modem_chat *chat, char **argv, uint16_t argc,
                               void *user_data)
{
    struct bg9x_ssl_modem_data *data = (struct bg9x_ssl_modem_data *)user_data;
    int err = try_atoi(argv[1]);
    if (err != 0)
        LOG_ERR("Modem error: %s: %s", argv[1], argv[2]);
    else
        LOG_DBG("Modem returned Operation succeeded");

    data->last_error = err;
}

MODEM_CHAT_MATCH_DEFINE(get_error_match, "+QIGETERROR", ",", get_error_match_cb);

MODEM_CHAT_SCRIPT_CMDS_DEFINE(bg9x_fetch_error_chat_script_cmds,
                              MODEM_CHAT_SCRIPT_CMD_RESP("AT+QIGETERROR", get_error_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP("", ok_match));

MODEM_CHAT_SCRIPT_DEFINE(bg9x_fetch_error_chat_script, bg9x_fetch_error_chat_script_cmds,
                         abort_matches, modem_cellular_chat_callback_handler, 1);

static int bg9x_ssl_fetch_error(struct bg9x_ssl_modem_data *data)
{
    return modem_run_script_and_wait(data, &bg9x_fetch_error_chat_script);
}

static void get_ssl_state_match_cb(struct modem_chat *chat, char **argv, uint16_t argc,
                                   void *user_data)
{
    struct bg9x_ssl_modem_data *data = (struct bg9x_ssl_modem_data *)user_data;
    int ssl_state = try_atoi(argv[6]);
    if (argc < 7 || ssl_state < 0)
    {
        LOG_ERR("Invalid ssl state response");
        return;
    }

    LOG_DBG("ssl state = %s", ssl_state_to_string(atoi(argv[6])));
    ssl_state = atoi(argv[6]);
    data->socket_state = ssl_state;

    if (ssl_state == SSL_STATE_CLOSING)
    {
        bg9x_ssl_close_socket(data);
    }
}

MODEM_CHAT_MATCH_DEFINE(get_ssl_state_match, "+QSSLSTATE", ",", get_ssl_state_match_cb);

MODEM_CHAT_SCRIPT_CMDS_DEFINE(bg9x_fetch_state_chat_script_cmds,
                              MODEM_CHAT_SCRIPT_CMD_RESP("AT+QSSLSTATE=1", get_ssl_state_match),
                              MODEM_CHAT_SCRIPT_CMD_RESP("", ok_match), );

MODEM_CHAT_SCRIPT_DEFINE(bg9x_fetch_state_chat_script, bg9x_fetch_state_chat_script_cmds,
                         abort_matches, modem_cellular_chat_callback_handler, 2);

static int bg9x_ssl_update_socket_state(struct bg9x_ssl_modem_data *data)
{
    return modem_run_script_and_wait(data, &bg9x_fetch_state_chat_script);
}

/*
 * =======================================================================
 *                          MODEM SOCKET SEND
 * =======================================================================
 * This contains code for sending data on a socket
 *
 * This implements sending in buffer access mode. First we request to send
 * data of size X. The modem opens up a prompt ">".
 * Then we send the data in chunks of size Y on the modem uart pipe until
 * we have X. On that point the modem should acknowledge the data with
 * "SEND OK" and we are done.
 * ========================================================================
 */

MODEM_CHAT_MATCH_DEFINE(send_ok_match, "SEND OK", "", NULL);

// AT+QSSLSEND=<clientID>,<sendlen>
char socket_send_cmd_buf[sizeof("AT+QSSLSEND=##,####")];
MODEM_CHAT_SCRIPT_CMDS_DEFINE(bg9x_socket_send_chat_script_cmds,
                              MODEM_CHAT_SCRIPT_CMD_RESP_NONE(socket_send_cmd_buf, 300),
                              MODEM_CHAT_SCRIPT_CMD_RESP("", send_ok_match), );

MODEM_CHAT_SCRIPT_DEFINE(bg9x_socket_send_chat_script, bg9x_socket_send_chat_script_cmds,
                         abort_matches, modem_cellular_chat_callback_handler, 10);

static int bg9x_ssl_socket_send(struct bg9x_ssl_modem_data *data, const uint8_t *buf, size_t len)
{
    int transmitted = 0;
    int ret;

    if (data->socket_state != SSL_STATE_CONNECTED)
    {
        LOG_ERR("Socket is not open");
        return -ENOTCONN;
    }

    // TODO: third paramter is socket, we can have more than one (0-11)
    snprintk(socket_send_cmd_buf, sizeof(socket_open_cmd_buf), "AT+QSSLSEND=1,%d", len);

    // TODO: Modem might not respond with prompt (">") on time. curretly I don't know how to check it
    ret = modem_chat_script_run(&data->chat, &bg9x_socket_send_chat_script);
    if (ret != 0)
        return ret;

    // TODO: check if modem responded with prompt (">") on time
    k_sleep(K_MSEC(320));
    LOG_INF("Transmitting....");
    transmitted = transmit_data(data, buf, len);
    if (transmitted < len)
    {
        LOG_ERR("Failed to transmit all data. transmitted: %d out of %d", transmitted, len);
        k_sem_reset(&data->script_sem);
        return transmitted;
    }

    ret = wait_on_modem_event(data, SCRIPT_FINISHED, K_SECONDS(5));
    if (ret < 0)
    {
        bg9x_ssl_fetch_error(data);
        bg9x_ssl_update_socket_state(data);
        if (data->socket_state != SSL_STATE_CONNECTED)
        {
            LOG_ERR("Socket diconnected while sending");
            return -ENOTCONN;
        }

        LOG_ERR("Failed to send data: %d. last modem err = %d", ret, data->last_error);
        return ret;
    }

    return transmitted;
}

/*
 * =======================================================================
 *                          MODEM SOCKET RECEIVE
 * =======================================================================
 * This contains code for receiving data over a socket
 *
 * This code is a bit complicated and should be reviewed with care. The problem is
 * that the chat mechanism does not handle unstructured data. So in order to receive
 * data from the pipe, we need to detach the pipe from the chat and parse it manually.
 *
 * First an unsolicited command is received from the modem that data is ready.
 * Than we detach the chat and manually send AT+QSSLRECV=1,<size> to the modem.
 * We leave enough place in the buffer for "AT+QSSLRECV: <size>\r\n" that appears
 * before the data and "\r\n\r\nOK\r\n" that appears after the data.
 * This should also check if after the data there is a socket closed message
 * (+QSSLURC: "closed") and set the socket_connected flag to false if so
 * ========================================================================
 */

// check if buffer contains socket close
bool is_recv_socket_close(struct bg9x_ssl_modem_data *data)
{
    size_t size = data->pipe_recv_total;
    const char *buf = data->data_to_receive;

    if (size < ((sizeof("+QSSLURC: \"closed\"") - 1) + sizeof("\r\n+QSSLRECV: #\r\n")))
        return false;

    return memmem(buf, size, "\r\n+QSSLURC: \"closed\"", strlen("\r\n+QSSLURC: \"closed\"")) != NULL;
}

// check if buffer ends with "\r\n\r\nOK or \r\n+QSSLRECV: #\r\n"
bool is_recv_finished(struct bg9x_ssl_modem_data *data)
{
    size_t size = data->pipe_recv_total;
    const char *buf = data->data_to_receive;

    if (size < ((sizeof("\r\n\r\nOK\r\n") - 1) + sizeof("\r\n+QSSLRECV: #\r\n")))
        return false;

    const char *read_end = memmem(buf, size, "\r\n\r\nOK\r\n", strlen("\r\n\r\nOK\r\n"));

    return read_end != NULL;
}

int parse_recv_size(const char *buf, size_t size)
{
    if (size < 20)
        return -EINVAL;

    const char *start = strnstr(buf, "+QSSLRECV: ", 20);
    if (start == NULL)
        return -EINVAL;

    start += strlen("+QSSLRECV: ");
    return try_atoi(start);
}

const char *get_recv_data_start_pos(const char *buf, size_t size)
{
    if (size < 20)
        return NULL;

    const char *first_occurrence = strnstr(buf, "\r\n", 20);
    if (first_occurrence == NULL)
        return NULL;

    const char *second_occurrence = strnstr(first_occurrence + 2, "\r\n", 20);
    if (second_occurrence == NULL)
        return NULL;

    return second_occurrence + 2;
}

int parse_and_extract_recv_data(struct bg9x_ssl_modem_data *data)
{
    const char *start_pos;
    char *end_pos;
    int response_recv_size;
    int actual_recv_size;

    // get position of data start after "\r\nqsslrecv: SIZE\r\n"
    start_pos = get_recv_data_start_pos(data->data_to_receive, data->pipe_recv_total);
    if (start_pos == NULL || start_pos == data->data_to_receive)
    {
        LOG_ERR("Failed to parse recv response");
        return -EINVAL;
    }

    LOG_DBG("data start position %d", start_pos - data->data_to_receive);

    // get the SIZE of the data to receive from "\r\n+qsslrecv: SIZE\r\n"
    response_recv_size = parse_recv_size(data->data_to_receive, data->pipe_recv_total);
    if (response_recv_size < 0)
    {
        LOG_ERR("Failed to parse recv size");
        return response_recv_size;
    }

    // In case response size == 0, one "/r/n" is ommitted and should be ignored
    if (response_recv_size == 0)
    {
        start_pos -= 2;
    }

    LOG_DBG("response recv size %d", response_recv_size);

    end_pos = memmem(start_pos, data->pipe_recv_total - (start_pos - data->data_to_receive), "\r\n\r\nOK\r\n", strlen("\r\n\r\nOK\r\n"));
    if (end_pos == NULL)
    {
        LOG_ERR("Failed to parse recv response end position");
        return -EINVAL;
    }

    *end_pos = '\0';

    // get size of data between "\r\n+qsslrecv: SIZE\r\n" and "\r\n\r\nOK\r\n"
    actual_recv_size = end_pos - start_pos;
    if (actual_recv_size < 0)
    {
        LOG_ERR("Invalid recv size: %d", actual_recv_size);
        return -EINVAL;
    }

    if (actual_recv_size != response_recv_size)
    {
        LOG_ERR("Received data size mismatch. expected: %d, actual: %d", response_recv_size, actual_recv_size);
        return -EINVAL;
    }

    LOG_DBG("Received total bytes %d", actual_recv_size);

    // move data to the beginning of the buffer
    memmove(data->data_to_receive, start_pos, actual_recv_size);

    return actual_recv_size;
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

        if (ret < 0)
            LOG_ERR("Pipe failed to receive data: %d", ret);

        LOG_DBG("pipe received %d bytes", ret);
        data->pipe_recv_total += ret;

        if (is_recv_socket_close(data))
        {
            LOG_INF("socket closed while reading");
            notify_modem_event(data, RECV_READY, -ECONNRESET);
            return;
        }

        if (is_recv_finished(data))
        {
            notify_modem_event(data, RECV_READY, 0);
            return;
        }

        break;

    default:
        LOG_ERR("unexpected pipe event %d, event", event);
    }
}

static int bg9x_ssl_socket_recv(struct bg9x_ssl_modem_data *data, uint8_t *buf, size_t requested_size, k_timeout_t timeout)
{
    int ret;
    char socket_recv_cmd_buf[sizeof("AT+QSSLRECV=##,####")];
    bool should_close_connection = false;
    size_t recv_buf_ability = sizeof(data->uart_backend_receive_buf) - strlen("\r\n+QSSLRECV: ####\r\n") - sizeof("\r\n\r\nOK\r\n");
    size_t max_len = requested_size > recv_buf_ability ? recv_buf_ability : requested_size;

    if (data->socket_state != SSL_STATE_CONNECTED)
    {
        LOG_WRN("called recv when socket is not connected");
        return 0;
    }

    // This waits on unsolicited command +QSSLURC: "recv"
    if (!data->socket_has_data)
    {
        k_timeout_t t = data->socket_blocking ? timeout : K_NO_WAIT;
        ret = wait_on_modem_event(data, RECV_READY, t);
        if (ret < 0)
            return -EAGAIN;
    }

    data->socket_has_data = true;
    data->data_to_receive = buf;
    data->data_to_receive_size = max_len;
    data->pipe_recv_total = 0;

    modem_chat_release(&data->chat);
    modem_pipe_attach(data->uart_pipe, pipe_recv_cb, data);

    // send the recv at command with the size of the buffer or the max uart receive buffer
    snprintk(socket_recv_cmd_buf, sizeof(socket_recv_cmd_buf), "AT+QSSLRECV=1,%d\r", max_len);

    // send request for reading data
    LOG_INF("Sending %s...", socket_recv_cmd_buf);
    ret = modem_pipe_transmit(data->uart_pipe, socket_recv_cmd_buf, strlen(socket_recv_cmd_buf));
    if (ret < 0)
    {
        LOG_ERR("Failed to transmit QSSLRECV: %d", ret);
        goto exit;
    }

    // wait for reading until ending "/r/n/r/nOK/r/n" or socket closed
    ret = wait_on_modem_event(data, RECV_READY, timeout);
    if (ret == -ECONNRESET)
        should_close_connection = true;
    else if (ret < 0)
        goto exit;

    ret = parse_and_extract_recv_data(data);
    if (ret < 0)
    {
        LOG_ERR("Failed to parse and extract recv data: %d", ret);

        // parse failed and connection closed -> connection was reset mid recv
        if (should_close_connection)
            ret = -ECONNRESET;

        goto exit;
    }

    if (ret == 0)
    {
        data->socket_has_data = false;
        k_poll_signal_reset(&data->sig_data_ready);
        if (data->socket_blocking == false)
            ret = -EAGAIN;
    }

exit:
    modem_pipe_release(data->uart_pipe);
    modem_chat_attach(&data->chat, data->uart_pipe);
    k_sem_reset(&data->recv_sem);

    if (should_close_connection)
        bg9x_ssl_close_socket(data);

    return ret;
}

int bg9x_ssl_modem_interface_start(struct bg9x_ssl_modem_data *data)
{
    int ret;

    ret = bg9x_ssl_configure(data);
    if (ret < 0)
    {
        LOG_ERR("Failed to configure modem: %d", ret);
        return ret;
    }

    ret = bg9x_ssl_modem_start(data);

    return ret;
}

/*
 * =======================================================================
 *                          Network IF and Socket Offloading
 * =======================================================================
 * ========================================================================
 */

static int offload_connect(void *obj, const struct sockaddr *addr, socklen_t addrlen)
{
    struct bg9x_ssl_modem_data *data = (struct bg9x_ssl_modem_data *)obj;
    struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
    int ret;
    char ip[INET_ADDRSTRLEN];
    uint16_t port;

    if (!addr || addrlen != sizeof(struct sockaddr_in))
    {
        LOG_ERR("Invalid address");
        return -EINVAL;
    }

    if (inet_ntop(AF_INET, &(addr_in->sin_addr), ip, INET_ADDRSTRLEN) == NULL)
    {
        LOG_ERR("Failed to convert address to string");
        return -EINVAL;
    }

    port = ntohs(addr_in->sin_port);

    ret = bg9x_ssl_open_socket(data, ip, port);
    if (ret != 0)
    {
        LOG_ERR("Failed to open socket");
        errno = -ret;
        return ret;
    }

    return 0;
}

static int offload_close(void *obj)
{
    struct bg9x_ssl_modem_data *data = (struct bg9x_ssl_modem_data *)obj;

    if (data->fd > 0)
    {
        z_free_fd(data->fd);
        data->fd = -1;
    }

    int ret = bg9x_ssl_close_socket(data);
    errno = -ret;
    return ret;
}

static ssize_t offload_recvfrom(void *obj, void *buf, size_t len,
                                int flags, struct sockaddr *from,
                                socklen_t *fromlen)
{
    struct bg9x_ssl_modem_data *data = (struct bg9x_ssl_modem_data *)obj;

    int ret;

    // TODO: check that socket source matches the source in the socket (received in offload_connect)

    ret = bg9x_ssl_socket_recv(data, (uint8_t *)buf, len, K_FOREVER);
    if (ret < 0)
    {
        errno = -ret;
    }

    return ret;
}

static ssize_t offload_read(void *obj, void *buffer, size_t count)
{
    return offload_recvfrom(obj, buffer, count, 0, NULL, 0);
}

static ssize_t offload_sendto(void *obj, const void *buf, size_t len,
                              int flags, const struct sockaddr *to,
                              socklen_t tolen)
{
    struct bg9x_ssl_modem_data *data = (struct bg9x_ssl_modem_data *)obj;
    int ret;

    ret = bg9x_ssl_socket_send(data, (const uint8_t *)buf, len);
    if (ret < 0)
    {
        errno = -ret;
        LOG_ERR("Failed to send data");
    }

    return ret;
}

static ssize_t offload_sendmsg(void *obj, const struct msghdr *msg, int flags)
{
    struct bg9x_ssl_modem_data *data = (struct bg9x_ssl_modem_data *)obj;
    ssize_t sent = 0;
    int rc;

    LOG_DBG("msg_iovlen:%zd flags:%d", msg->msg_iovlen, flags);

    for (int i = 0; i < msg->msg_iovlen; i++)
    {
        const char *buf = msg->msg_iov[i].iov_base;
        size_t len = msg->msg_iov[i].iov_len;

        while (len > 0)
        {
            rc = offload_sendto(obj, buf, len, flags,
                                msg->msg_name, msg->msg_namelen);
            if (rc < 0)
            {
                if (data->socket_blocking == false)
                {
                    errno = -rc;
                    return rc;
                }

                if (rc == -EAGAIN)
                {
                    k_sleep(K_MSEC(200));
                }

                else
                {
                    sent = rc;
                    break;
                }
            }
            else
            {
                sent += rc;
                buf += rc;
                len -= rc;
            }
        }
    }

    return (ssize_t)sent;
}

static ssize_t offload_write(void *obj, const void *buffer, size_t count)
{
    return offload_sendto(obj, buffer, count, 0, NULL, 0);
}

int bg9x_ssl_getaddrinfo(const char *node, const char *service,
                         const struct zsock_addrinfo *hints,
                         struct zsock_addrinfo **res)
{
    if (node == NULL || res == NULL)
    {
        LOG_ERR("Invalid arguments");
        return -EINVAL;
    }

    if (hints && hints->ai_family != AF_INET)
    {
        LOG_ERR("Not suppoerted family");
        errno = EAFNOSUPPORT;
        return -ENOTSUP;
    }

    return bg9x_ssl_dns_resolve(&modem_data, node, res);
}

void bg9x_ssl_freeaddrinfo(struct zsock_addrinfo *res)
{
    if (res == NULL)
    {
        return;
    }

    __ASSERT(res == modem_data.last_resolved_addr_info, "Invalid addrinfo! must be last resolved addrinfo");

    while (res != NULL)
    {
        struct zsock_addrinfo *next = res->ai_next;
        free(res->ai_addr);
        free(res);
        res = next;
    }

    modem_data.last_resolved_addr_info = NULL;
    modem_data.resolved_addr_count = 0;
}

int ioctl_poll_prepare(struct bg9x_ssl_modem_data *data, struct zsock_pollfd *pfd, struct k_poll_event **pev,
                       struct k_poll_event *pev_end)
{
    data->socket_blocking = false;
    if (pfd->events & ZSOCK_POLLIN)
    {
        if (*pev == pev_end)
        {
            errno = ENOMEM;
            return -1;
        }

        k_poll_event_init(*pev, K_POLL_TYPE_SIGNAL, K_POLL_MODE_NOTIFY_ONLY,
                          &data->sig_data_ready);
        (*pev)++;
    }

    if (pfd->events & ZSOCK_POLLOUT)
    {
        if (*pev == pev_end)
        {
            errno = ENOMEM;
            return -1;
        }
        /* Not Implemented */
        errno = ENOTSUP;
        return -1;
    }

    return 0;
}

int ioctl_poll_update(struct zsock_pollfd *pfd,
                      struct k_poll_event **pev)
{
    if (pfd->events & ZSOCK_POLLIN)
    {
        if ((*pev)->state != K_POLL_STATE_NOT_READY)
        {
            pfd->revents |= ZSOCK_POLLIN;
        }
        (*pev)++;
    }

    if (pfd->events & ZSOCK_POLLOUT)
    {
        /* Not implemented, but the modem socket is always ready to transmit,
         * so set the revents
         */
        pfd->revents |= ZSOCK_POLLOUT;
        (*pev)++;
    }

    return 0;
}

static int offload_ioctl(void *obj, unsigned int request, va_list args)
{
    switch (request)
    {
    case ZFD_IOCTL_POLL_PREPARE:
    {
        LOG_DBG("POLL PREPARE");
        struct zsock_pollfd *pfd;
        struct k_poll_event **pev;
        struct k_poll_event *pev_end;

        pfd = va_arg(args, struct zsock_pollfd *);
        pev = va_arg(args, struct k_poll_event **);
        pev_end = va_arg(args, struct k_poll_event *);

        return ioctl_poll_prepare((struct bg9x_ssl_modem_data *)obj, pfd, pev, pev_end);
    }
    case ZFD_IOCTL_POLL_UPDATE:
    {
        LOG_DBG("POLL UPDATE");
        struct zsock_pollfd *pfd;
        struct k_poll_event **pev;

        pfd = va_arg(args, struct zsock_pollfd *);
        pev = va_arg(args, struct k_poll_event **);

        return ioctl_poll_update(pfd, pev);
    }
    case ZFD_IOCTL_POLL_OFFLOAD:
    {
        LOG_DBG("POLL PREPARE");
        return -ENOTSUP;
    }

    default:
        errno = EINVAL;
        return -1;
    }
}

static const struct socket_op_vtable offload_socket_fd_op_vtable = {
    .fd_vtable = {
        .read = offload_read,
        .write = offload_write,
        .close = offload_close,
        .ioctl = offload_ioctl,
    },
    .bind = NULL,
    .connect = offload_connect,
    .sendto = offload_sendto,
    .recvfrom = offload_recvfrom,
    .listen = NULL,
    .accept = NULL,
    .sendmsg = offload_sendmsg,
    .getsockopt = NULL,
    .setsockopt = NULL,
};

const struct socket_dns_offload dns_vtable = {
    .getaddrinfo = bg9x_ssl_getaddrinfo,
    .freeaddrinfo = bg9x_ssl_freeaddrinfo,
};

/* Setup the Modem NET Interface. */
static void modem_net_iface_init(struct net_if *iface)
{
    const struct device *dev = net_if_get_device(iface);
    struct bg9x_ssl_modem_data *data = dev->data;

    /* Direct socket offload used instead of net offload: */
    net_if_set_link_addr(iface, data->mac_addr,
                         sizeof(data->mac_addr),
                         NET_LINK_ETHERNET);
    data->net_iface = iface;

    socket_offload_dns_register(&dns_vtable);
    net_if_socket_offload_set(iface, offload_socket);
}

/*
 * =======================================================================
 *                          Device power management
 * =======================================================================
 * This should be respnsible for turning device on/off upon request
 * Should this also be responsible for setting the device as network interface?
 * ========================================================================
 */

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
    gpio_pin_set_dt(&config->power_gpio, 1);
    k_sleep(K_MSEC(config->power_pulse_duration_ms));

    gpio_pin_set_dt(&config->power_gpio, 0);
    k_sleep(K_MSEC(config->startup_time_ms));

    LOG_DBG("Modem power pulse completed");

    if (bg9x_ssl_modem_interface_start(data) < 0)
    {
        LOG_ERR("Failed to start modem interface");
        return -EINVAL;
    }

    return 0;
}

int bg9x_ssl_modem_power_off(const struct device *dev)
{
    // TODO
    return 0;
}

static int bg9x_ssl_pm_action(const struct device *dev, enum pm_device_action action)
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

#if CONFIG_BG9X_MODEM_SSL_SECURITY_LEVEL > 0
    data->ca_cert = sizeof(ca_cert_default) > 0 ? ca_cert_default : NULL;
#endif
#if CONFIG_BG9X_MODEM_SSL_SECURITY_LEVEL > 1
    data->client_cert = sizeof(client_cert_default) > 0 ? client_cert_default : NULL;
    data->client_key = sizeof(client_key_default) > 0 ? client_key_default : NULL;
#endif

    data->socket_blocking = true;
    data->socket_state = SSL_STATE_INITIAL;

    k_sem_init(&data->script_sem, 0, 1);
    k_sem_init(&data->registration_sem, 0, 1);
    k_sem_init(&data->recv_sem, 0, 1);
    k_poll_signal_init(&data->sig_data_ready);

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

static struct offloaded_if_api api_funcs = {
    .iface_api.init = modem_net_iface_init,
};

static bool offload_is_supported(int family, int type, int proto)
{
    // support IPv4 and IPv6
    if (family != AF_INET && family != AF_INET6)
        return false;

    // support only TCP
    if (type != SOCK_STREAM)
        return false;

    if (CONFIG_BG9X_MODEM_SSL_SECURITY_LEVEL == 0)
        return proto == IPPROTO_TCP;

    // support these tls versions. determined with AT+QSSLCFG="sslversion",4 == (TLS 1.0) | (TLS 1.1) | (TLS 1.2)
    if (proto != IPPROTO_TCP && proto != IPPROTO_TLS_1_0 && proto != IPPROTO_TLS_1_1 && proto != IPPROTO_TLS_1_2)
        return false;

    return true;
}

static int offload_socket(int family, int type, int proto)
{
    int fd = z_reserve_fd();
    if (fd < 0)
    {
        return -EMFILE;
    }

    z_finalize_fd(fd, &modem_data, (const struct fd_op_vtable *)&offload_socket_fd_op_vtable);

    modem_data.fd = fd;
    return fd;
}

/* Register the device with the Power Management module. */
PM_DEVICE_DT_INST_DEFINE(0, bg9x_ssl_pm_action);

/* Register the device with the Networking stack. */
NET_DEVICE_DT_INST_OFFLOAD_DEFINE(0, bg9x_ssl_init, PM_DEVICE_DT_INST_GET(0),
                                  &modem_data, &modem_config,
                                  80, // priority copied from bg9x_modem
                                  &api_funcs, MODEM_MAX_DATA_LENGTH);

/* Register NET sockets. */
NET_SOCKET_OFFLOAD_REGISTER(quectel_bg9x_ssl, CONFIG_NET_SOCKETS_OFFLOAD_PRIORITY,
                            AF_UNSPEC, offload_is_supported, offload_socket);

/* =========================== Device Init ============================================= */