# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(cellular_modem)

target_sources(app PRIVATE src/main.c src/bg9x_ssl.c)

# create byte arrays for each cert and key file

set(gen_dir ${ZEPHYR_BINARY_DIR}/include/generated/)

# If the security level is 0, then we don't need to generate any files
# If the security level is 1, then we need to generate the CA cert file
# We generate an empty file if the CA cert is not specified
# Do the same for the client cert and key files if the security level is 2

if(${CONFIG_BG9X_MODEM_SSL_SECURITY_LEVEL} GREATER_EQUAL 1)

    if(NOT DEFINED CONFIG_BG9X_MODEM_SSL_CA_CERT)
        file(WRITE ${gen_dir}/bg95_ssl_ca_cert.inc "")
    else()
        generate_inc_file_for_target(
                                    app
                                    ${CMAKE_CURRENT_SOURCE_DIR}/${CONFIG_BG9X_MODEM_SSL_CA_CERT}
                                    ${gen_dir}/bg95_ssl_ca_cert.inc)
    endif()

endif()

if(${CONFIG_BG9X_MODEM_SSL_SECURITY_LEVEL} GREATER_EQUAL 2)
    if(NOT DEFINED CONFIG_BG9X_MODEM_SSL_CLIENT_CERT)
        file(WRITE ${gen_dir}/bg95_ssl_client_cert.inc "")
    else()
        generate_inc_file_for_target(
                                    app
                                    ${CMAKE_CURRENT_SOURCE_DIR}/${CONFIG_BG9X_MODEM_SSL_CLIENT_CERT}
                                    ${gen_dir}/bg95_ssl_client_cert.inc)
    endif()

    if(NOT DEFINED CONFIG_BG9X_MODEM_SSL_CLIENT_KEY)
        file(WRITE ${gen_dir}/bg95_ssl_ca_cert.bg95_ssl_client_key "")
    else()
        generate_inc_file_for_target(
                                    app
                                    ${CMAKE_CURRENT_SOURCE_DIR}/${CONFIG_BG9X_MODEM_SSL_CLIENT_KEY}
                                    ${gen_dir}/bg95_ssl_client_key.inc)
    endif()
endif()