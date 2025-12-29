# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025, Lux Industries Inc

add_executable(example_basic example_basic.c)
target_link_libraries(example_basic ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libluxfhe${SHARED_LIB_EXT})
target_include_directories(example_basic PRIVATE ${CMAKE_SOURCE_DIR}/include)
add_dependencies(example_basic luxfhe_shared)

add_executable(example_comparison example_comparison.c)
target_link_libraries(example_comparison ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libluxfhe${SHARED_LIB_EXT})
target_include_directories(example_comparison PRIVATE ${CMAKE_SOURCE_DIR}/include)
add_dependencies(example_comparison luxfhe_shared)
