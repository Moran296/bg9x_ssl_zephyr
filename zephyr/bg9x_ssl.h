#ifndef BG9X_SSL_H
#define BG9X_SSL_H

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

#ifdef __cplusplus
}
#endif

#endif // BG9X_SSL_H