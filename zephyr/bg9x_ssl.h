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

#ifdef __cplusplus
}
#endif

#endif // BG9X_SSL_H