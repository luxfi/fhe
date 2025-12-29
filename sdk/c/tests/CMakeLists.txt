# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025, Lux Industries Inc

add_executable(test_basic test_basic.c)
target_link_libraries(test_basic ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libluxfhe${SHARED_LIB_EXT})
target_include_directories(test_basic PRIVATE ${CMAKE_SOURCE_DIR}/include)
add_dependencies(test_basic luxfhe_shared)

add_test(NAME basic_test COMMAND test_basic)
