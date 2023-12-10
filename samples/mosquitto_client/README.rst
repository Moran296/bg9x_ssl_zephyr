BG9X SSL Mosquitto Publisher Sample
###################################

Overview
********
This is a sample that demonstrates how to use the BG9X modem
with mosquitto mqtt client to publish messages to a broker
using a secure connection.

Prerequisites
*************
1. A BG9X modem with SIM, antenna and a valid APN.
2. CA certificate for the broker
3. Client certificate and key (optional)


Mosquitto broker setup
**********************
The sample uses `mosquitto test broker <https://test.mosquitto.org/>`_
to demonstrate mqtt publish functionality.

For port 8883 (encrypted, unauthenticated), only ca cert is required.
It is provided in the sample main directory as 'mosquitto.org.crt'.
In prj.conf, set::

        CONFIG_BG9X_SSL_MODEM_SECURITY_LEVEL=1
        CONFIG_BG9X_SSL_MODEM_CA_CERT="mosquitto.org.crt"

For port 8884 (encrypted, authenticated), client cert and key are also required.
Follow the steps `here <https://test.mosquitto.org/ssl/>`_
In prj.conf, set::

        CONFIG_BG9X_SSL_MODEM_SECURITY_LEVEL=2
        CONFIG_BG9X_SSL_MODEM_CA_CERT="mosquitto.org.crt"
        CONFIG_BG9X_SSL_MODEM_CLIENT_CERT="client.crt"
        CONFIG_BG9X_SSL_MODEM_CLIENT_KEY="client.key"

To test the sample, run mosquitto client in a terminal window,
according to the port and seclevel::

        mosquitto_sub -h test.mosquitto.org -p 8883 -t "bg9xssl" -d --cafile mosquitto.org.crt
        mosquitto_sub -h test.mosquitto.org -p 8884 -t "bg9xssl" -d --cafile mosquitto.org.crt --cert client.crt --key client.key

You should see the output as messages published by the sample as::
        BG9XSSL:QoS0

        BG9XSSL:QoS1

        BG9XSSL:QoS2


        ...



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

Next, the UART API must be specified using ``CONFIG_UART_ASYNC_API=y``. The driver doesn't support UART polling.
Lastly, the APN must be configured using ``BG9X_MODEM_SSL_APN=""``.
