#ifndef BG9X_SSL_H
#define BG9X_SSL_H

#include <zephyr/modem/chat.h>
#include <zephyr/net/net_ip.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /* BG9x SSL Connection Options

        when calling set opt function:

        int conn_mgr_if_set_opt(struct net_if *iface, int optname, const void *optval, size_t optlen)

        the name of the option is passed in optname and is one of the following enum bg9x_ssl_conn_options values
        the optval is described in the comments below
    */

    enum bg9x_ssl_conn_options
    {
        // optval is const char*, optlen is strlen(optval). dafault from Kconfig
        BG9X_SSL_CONNECTIVITY_APN,
        BG9X_SSL_CONNECTIVITY_USERNAME,
        BG9X_SSL_CONNECTIVITY_PASSWORD,

        // optval is a pointer to variable of type bg9x_ssl_connectivity_network_mode. optlen not used
        BG9X_SSL_CONNECTIVITY_NETWORK_MODE,
    };

    enum bg9x_ssl_connectivity_network_mode
    {
        BG9X_SSL_CONNECTIVITY_NETWORK_MODE_AUTO = 0,
        BG9X_SSL_CONNECTIVITY_NETWORK_MODE_GSM_ONLY = 1,
        BG9X_SSL_CONNECTIVITY_NETWORK_MODE_LTE_ONLY = 3,
    };

    enum cellular_network_type
    {
        CELLULAR_NETWORK_NONE,
        CELLULAR_NETWORK_GSM,
        CELLULAR_NETWORK_NBIOT,
        CELLULAR_NETWORK_LTE_M,
    };

    struct modem_connection_info
    {
        enum cellular_network_type network_type;
        struct in_addr ipv4addr;
        char iccid[24];
        char imei[16];
        int rssi;
        int rsrp;
        int rsrq;
        int sinr;
    };

    /*
        @ brief:    get the modem connection info
        @ param:    info - pointer to a modem_connection_info struct
        @ return:   0 on success,
                    -ENETDOWN if the modem is not connected to the network
                    -ETIMEDOUT if the modem is connected to the network but the connection info is not available
                    negative error code on failure

        @ note:     this function is blocking and might take a minute or more so take care when calling it
    */
    int bg9x_ssl_get_connection_info(struct modem_connection_info *info);

    // functions for using the BG9x modem uart pipe for different purposes

    /*
        @ brief:    attach a different chat to the modem uart pipe
        @ param:    chat - pointer to a modem_chat struct
        @ return:   none

        @ note:     this detaches thessl chat from the modem uart pipe
                    Afer finishing the chat, the ssl chat must be re-attached to the modem uart pipe
    */
    void bg9x_control_attach_user_chat(struct modem_chat *chat);

    /*
        @ brief:    detach the ssl chat from the modem uart pipe
        @ param:    none
        @ return:   none

        @ note:     this attaches the default ssl chat to the modem uart pipe
    */
    void bg9x_control_detach_user_chat(void);

    typedef void (*bridge_resp_cb)(const char *response, size_t len);
    void bg9x_control_bridge_start(bridge_resp_cb);
    void bg9x_control_bridge_stop();
    int bg9x_control_bridge_send(const char *cmd, size_t len);

#ifdef __cplusplus
}
#endif

#endif // BG9X_SSL_H