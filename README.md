# 📡 Out of tree BG9x modem driver with SSL socket offloading for Zephyr RTOS

*Note: This repository is a work in progress*

## Overview

This repository contains the out of tree BG9x modem driver with SSL socket offloading for Zephyr RTOS.
### This includes the next features:
- SSL socket offloading as a Zephyr network interface
- CA certificate, client certificate and client key file upload to the modem
- Socket offloading for client SSL sockets
- Setsockopt runtime certificate provisioning support
- Currently only one socket at a time is supported
- PM device power management support
- DNS resolve offloading support (getaddrinfo)
- Kconfig support for cert and key file path auto provisioning
- Sync behavior - all API is blocking (socket can be configured as non-blocking and polled)
- Two samples are included:
  - MQTT publisher sample (test.mosquitto.org)
  - Azure IOT Hub sample application using NRF IOT Hub library

Also included is a sample application that demonstrates the driver. Currently the only sample application is
Zephyr's MQTT publisher sample with SSL socket offloading.

### TODO features
- [ ] Aquire modem info on startup (IMEI, IMSI, etc.)
- [ ] More than one socket at a time
- [ ] Test and use with BG96
- [ ] HTTPS sample application

## Tested with
- BG95M3 on NRF52840
- Nordic SDK v2.5.0 (Zephyr v3.4.99-ncs1)


## Usage
### Module configuration
TODO: Describe how to use the driver.

### Driver configuration
Enable the driver in the project's prj.conf file:
```
CONFIG_BG9X_MODEM_SSL=y
```
Next, configure the required security level:
- For encryption without client authentication, security level 1 is required and CA certificate is mandatory.
```
CONFIG_BG9X_SSL_MODEM_SECURITY_LEVEL=1
CONFIG_BG9X_SSL_MODEM_CA_CERT="mosquitto.org.crt"
```
- For encryption with client authentication, security level 2 is required and CA certificate, client certificate and client key are mandatory.
```
CONFIG_BG9X_SSL_MODEM_SECURITY_LEVEL=2
CONFIG_BG9X_SSL_MODEM_CA_CERT="mosquitto.org.crt"
CONFIG_BG9X_SSL_MODEM_CLIENT_CERT="client.crt"
CONFIG_BG9X_SSL_MODEM_CLIENT_KEY="client.key"
```
- For no encryption, security level 0 is required and no certificates are required.
```
CONFIG_BG9X_SSL_MODEM_SECURITY_LEVEL=0
```

Other required configuration options:
```
CONFIG_UART_ASYNC_API=y
CONFIG_BG9X_SSL_MODEM_APN="internet"

# for debug prints
CONFIG_MODEM_LOG_LEVEL_DBG=y
```

### Device tree configuration
The driver reuires a bg9x modem node in a uart bus, for example:

```

/ {
        aliases {
        modem = &modem;
    };
}


&uart1 {
	compatible = "nordic,nrf-uarte";
	status = "okay";
	current-speed = <115200>;
	pinctrl-0 = <&uart1_default>;
	pinctrl-1 = <&uart1_sleep>;
	pinctrl-names = "default", "sleep";
	hw-flow-control;

	modem: modem {
		compatible = "quectel,bg95";
		mdm-power-gpios = <&gpio0 26 GPIO_ACTIVE_HIGH>;
		status = "okay";
	};
};

```





