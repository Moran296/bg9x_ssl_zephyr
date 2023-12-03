# SPDX-License-Identifier: Apache-2.0

if (CONFIG_BG9X_MODEM_SSL)

zephyr_include_directories(.)

  zephyr_library()
  zephyr_library_sources(bg9x_ssl.c)

# create byte arrays for each cert and key file

set(gen_dir ${ZEPHYR_BINARY_DIR}/include/generated/)

# If the security level is 0, then we don't need to generate any files
# If the security level is 1, then we need to generate the CA cert file
# We generate an empty file if the CA cert is not specified
# Do the same for the client cert and key files if the security level is 2

if(${CONFIG_BG9X_MODEM_SSL_SECURITY_LEVEL} GREATER_EQUAL 1)

    if(NOT DEFINED CONFIG_BG9X_MODEM_SSL_CA_CERT)
        message(WARNING "No CA cert file specified. SSL will not work")
        file(WRITE ${gen_dir}/bg95_ssl_ca_cert.inc "")
    elseif(NOT EXISTS ${CMAKE_SOURCE_DIR}/${CONFIG_BG9X_MODEM_SSL_CA_CERT})
        message(FATAL_ERROR "CA cert file '${CONFIG_BG9X_MODEM_SSL_CA_CERT}' was not found. Please make sure the file exists in the CMAKE_SOURCE_DIR directory (${CMAKE_SOURCE_DIR})")
    else()
        generate_inc_file_for_target(
                                    app
                                    ${CMAKE_SOURCE_DIR}/${CONFIG_BG9X_MODEM_SSL_CA_CERT}
                                    ${gen_dir}/bg95_ssl_ca_cert.inc)
    endif()

endif()

if(${CONFIG_BG9X_MODEM_SSL_SECURITY_LEVEL} GREATER_EQUAL 2)
    if(NOT DEFINED CONFIG_BG9X_MODEM_SSL_CLIENT_CERT)
        message(WARNING "No client cert file specified. SSL client authentication will not work")
        file(WRITE ${gen_dir}/bg95_ssl_client_cert.inc "")
    elseif(NOT EXISTS ${CMAKE_SOURCE_DIR}/${CONFIG_BG9X_MODEM_SSL_CLIENT_CERT})
        message(FATAL_ERROR "Client cert file '${CONFIG_BG9X_MODEM_SSL_CLIENT_CERT}' was not found. Please make sure the file exists in the CMAKE_SOURCE_DIR directory (${CMAKE_SOURCE_DIR})")
    else()
        generate_inc_file_for_target(
                                    app
                                    ${CMAKE_SOURCE_DIR}/${CONFIG_BG9X_MODEM_SSL_CLIENT_CERT}
                                    ${gen_dir}/bg95_ssl_client_cert.inc)
    endif()

    if(NOT DEFINED CONFIG_BG9X_MODEM_SSL_CLIENT_KEY)
        message(WARNING "No client key file specified. SSL client authentication will not work")
        file(WRITE ${gen_dir}/bg95_ssl_ca_cert.bg95_ssl_client_key "")
    elseif(NOT EXISTS ${CMAKE_SOURCE_DIR}/${CONFIG_BG9X_MODEM_SSL_CLIENT_KEY})
        message(FATAL_ERROR "Client key file '${CONFIG_BG9X_MODEM_SSL_CLIENT_KEY}' was not found. Please make sure the file exists in the CMAKE_SOURCE_DIR directory (${CMAKE_SOURCE_DIR})")
    else()
        generate_inc_file_for_target(
                                    app
                                    ${CMAKE_SOURCE_DIR}/${CONFIG_BG9X_MODEM_SSL_CLIENT_KEY}
                                    ${gen_dir}/bg95_ssl_client_key.inc)
    endif()
endif()

endif() # CONFIG_BG9X_MODEM_SSL
