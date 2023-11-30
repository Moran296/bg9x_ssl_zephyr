# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(cellular_modem)

target_sources(app PRIVATE src/main.c src/bg9x_ssl.c)

# create byte arrays for each cert and key file

set(gen_dir ${ZEPHYR_BINARY_DIR}/include/generated/)

if(${CONFIG_BG9X_MODEM_SSL_SECURITY_LEVEL} GREATER_EQUAL 1)

generate_inc_file_for_target(
                            app
                            ${CMAKE_CURRENT_SOURCE_DIR}/${CONFIG_BG9X_MODEM_SSL_CA_CERT}
                            ${gen_dir}/bg95_ssl_ca_cert.inc)
endif()

if(${CONFIG_BG9X_MODEM_SSL_SECURITY_LEVEL} GREATER_EQUAL 2)
generate_inc_file_for_target(
                            app
                            ${CMAKE_CURRENT_SOURCE_DIR}/${CONFIG_BG9X_MODEM_SSL_CLIENT_CERT}
                            ${gen_dir}/bg95_ssl_client_cert.inc)

generate_inc_file_for_target(
                            app
                            ${CMAKE_CURRENT_SOURCE_DIR}/${CONFIG_BG9X_MODEM_SSL_CLIENT_KEY}
                            ${gen_dir}/bg95_ssl_client_key.inc)
endif()