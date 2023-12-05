# SPDX-License-Identifier: Apache-2.0

if (CONFIG_BG9X_MODEM_SSL)

zephyr_include_directories(.)

  zephyr_library()
  zephyr_library_sources(bg9x_ssl.c)

# create byte arrays for each cert and key file

set(gen_dir ${ZEPHYR_BINARY_DIR}/include/generated/)

function(generate_cert_file CONFIG_NAME FILE_NAME)
    if(NOT DEFINED ${CONFIG_NAME} OR ${CONFIG_NAME} STREQUAL "")
        message(WARNING "No ${FILE_NAME} file specified. SSL will not work")
        file(WRITE ${gen_dir}/${FILE_NAME}.inc "")
    elseif(NOT EXISTS ${CMAKE_SOURCE_DIR}/${${CONFIG_NAME}})
        message(FATAL_ERROR "${FILE_NAME} file '${${CONFIG_NAME}}' was not found. Please make sure the file exists in the CMAKE_SOURCE_DIR directory (${CMAKE_SOURCE_DIR})")
    else()
        generate_inc_file_for_target(
                                    app
                                    ${CMAKE_SOURCE_DIR}/${${CONFIG_NAME}}
                                    ${gen_dir}/${FILE_NAME}.inc)
    endif()
endfunction()

# If the security level is 0, then we don't need to generate any files
# If the security level is 1, then we need to generate the CA cert file
# We generate an empty file if the CA cert is not specified
# We raise an error if the CA cert is specified but not found (at the base project cmakelists.txt directory)
# Do the same for the client cert and key files if the security level is 2

if(${CONFIG_BG9X_MODEM_SSL_SECURITY_LEVEL} GREATER_EQUAL 1)
    generate_cert_file(CONFIG_BG9X_MODEM_SSL_CA_CERT "bg95_ssl_ca_cert")
endif()

if(${CONFIG_BG9X_MODEM_SSL_SECURITY_LEVEL} GREATER_EQUAL 2)
    generate_cert_file(CONFIG_BG9X_MODEM_SSL_CLIENT_CERT "bg95_ssl_client_cert")
    generate_cert_file(CONFIG_BG9X_MODEM_SSL_CLIENT_KEY "bg95_ssl_client_key")
endif()


endif() # CONFIG_BG9X_MODEM_SSL
