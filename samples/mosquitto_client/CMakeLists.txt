# SPDX-License-Identifier: Apache-2.0

list(APPEND EXTRA_ZEPHYR_MODULES
  ${CMAKE_CURRENT_SOURCE_DIR}/../../
  )

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(bg9x_ssl_mosquitto_sample)

target_sources(app PRIVATE src/main.c)

target_compile_options(app PRIVATE -Wall -Werror -Wfatal-errors)