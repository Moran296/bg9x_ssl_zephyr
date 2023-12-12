# SPDX-License-Identifier: Apache-2.0

list(APPEND EXTRA_ZEPHYR_MODULES
  ${CMAKE_CURRENT_SOURCE_DIR}/../../
  )

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(bg9x_ssl_azure_sample)

target_sources(app PRIVATE src/main.c)

target_compile_options(app PRIVATE -Wall -Werror -Wfatal-errors)


# Script for generating the certificate files for runtime provisioning

set(gen_dir ${ZEPHYR_BINARY_DIR}/include/generated/)

function(generate_cert_file FILE_NAME FILE_TYPE)
    if(NOT EXISTS ${CMAKE_SOURCE_DIR}/${FILE_NAME})
        message(FATAL_ERROR "${FILE_TYPE} file '${FILE_NAME}' was not found. Please make sure the file exists in the CMAKE_SOURCE_DIR directory (${CMAKE_SOURCE_DIR})")
    else()
        generate_inc_file_for_target(
                                    app
                                    ${CMAKE_SOURCE_DIR}/${FILE_NAME}
                                    ${gen_dir}/${FILE_TYPE}.inc)
    endif()
endfunction()

# Replace "MY CA CERT FILE" with the name of your client key file
generate_cert_file("MY CA CERT FILE" "azure_ca_cert")

# Replace "MY CLIENT CERT FILE" with the name of your client key file
generate_cert_file("MY CLIENT CERT FILE" "azure_client_cert")

# Replace "MY CLIENT KEY FILE" with the name of your client key file
generate_cert_file("MY CLIENT KEY FILE" "azure_client_key")