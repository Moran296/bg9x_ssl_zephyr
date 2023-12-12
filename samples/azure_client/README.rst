BG9X SSL Azure Client Sample
############################

Overview
********
This is a sample that demonstrates how to use the BG9X modem
with NRF azure client library to connect to Azure IoT Hub. This is
a simplified version of the nrf/samples/net/azure_iot_hub sample
without DPS, Connection manager and with BG9X modem support. It also demonstrates runtime
certificate provisioning so certificates and key must be provided by the
user and written in the CMakeLists.txt file.

Prerequisites
*************
1. A BG9X modem with SIM, antenna and a valid APN.
2. CA certificate for the Azure IOT hub.
3. Client certificate and key for the device under test.
4. A valid Azure IOT hub and device identity.

IOT Hub Setup
*************

The IOT hub and device name must be configured in the prj.conf file::

        CONFIG_AZURE_IOT_HUB_HOSTNAME="MY AZURE IOT HUB.azure-devices.net"
        CONFIG_AZURE_IOT_HUB_DEVICE_ID="MY DEVICE ID"

Switch the values with the values for your IOT hub and device.

Certificate Provisioning
************************
For the sample to work, the user must provide CA cert, client cert and client key.
Please follow Azure documentation to get the certificates and keys.

The CmakeFile.txt in this sample includes a script that converts the certificates
and keys to a format that can be embedded as an include file. The files are used in main.c
to provision the certificates and keys at runtime using tls_credential subsystem and
CONFIG_MQTT_HELPER_SEC_TAG tag. Failure to supply the certificates and keys will result
in a build error.

For example, if your CA certificate is called azure-iot-test-only.root.ca.cert.pem,
In CMakeLists.txt, switch the following line::

        generate_cert_file("MY CA CERT FILE" "azure_ca_cert")

to::

        generate_cert_file("azure-iot-test-only.root.ca.cert.pem" "azure_ca_cert")

and so on for the client certificate and key.

**Do not use this method in production. In a real application, the certificates
and keys should be provisioned at runtime from a secure storage.**

Device Tree Setup
*****************

This sample uses the devicetree alias modem to identify
the modem instance to use. The sample also presumes that
the modem driver creates the only network interface.

Setup
*****

Start by setting up the devicetree with the required
devicetree node::

   /dts-v1/;

   / {
           aliases {
                   modem = &modem;
           };
   };

   &usart2 {
           pinctrl-0 = <&usart2_tx_pa2 &usart2_rx_pa3 &usart2_rts_pa1 &usart2_cts_pa0>;
           pinctrl-names = "default";
           current-speed = <115200>;
           hw-flow-control;
           status = "okay";

           modem: modem {
                   compatible = "quectel,bg9x";
                   mdm-power-gpios = <&gpioe 2 GPIO_ACTIVE_HIGH>;
                   status = "okay";
           };
   };

Next, the UART API must be specified using ``CONFIG_UART_ASYNC_API=y``.
 The driver doesn't support UART polling.

The APN must be configured using ``BG9X_MODEM_SSL_APN=""``.


