# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025, Lux Industries Inc
#
# CMake build system for LuxFHE C library

cmake_minimum_required(VERSION 3.16)
project(luxfhe
    VERSION 1.0.0
    DESCRIPTION "LuxFHE - Fully Homomorphic Encryption Library"
    LANGUAGES C CXX
)

# Options
option(LUXFHE_BUILD_SHARED "Build shared library" ON)
option(LUXFHE_BUILD_STATIC "Build static library" ON)
option(LUXFHE_BUILD_TESTS "Build tests" ON)
option(LUXFHE_BUILD_EXAMPLES "Build examples" ON)

# Find Go
find_program(GO_EXECUTABLE go REQUIRED)

# Get Go version
execute_process(
    COMMAND ${GO_EXECUTABLE} version
    OUTPUT_VARIABLE GO_VERSION_OUTPUT
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
message(STATUS "Found Go: ${GO_VERSION_OUTPUT}")

# Set output directories
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Include directory
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Platform-specific settings
if(WIN32)
    set(SHARED_LIB_EXT ".dll")
    set(STATIC_LIB_EXT ".lib")
    set(GO_BUILD_MODE "-buildmode=c-shared")
elseif(APPLE)
    set(SHARED_LIB_EXT ".dylib")
    set(STATIC_LIB_EXT ".a")
    set(GO_BUILD_MODE "-buildmode=c-shared")
else()
    set(SHARED_LIB_EXT ".so")
    set(STATIC_LIB_EXT ".a")
    set(GO_BUILD_MODE "-buildmode=c-shared")
endif()

# Build shared library from Go
if(LUXFHE_BUILD_SHARED)
    set(SHARED_LIB_NAME "luxfhe${SHARED_LIB_EXT}")
    set(SHARED_LIB_PATH "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/${SHARED_LIB_NAME}")
    
    add_custom_command(
        OUTPUT ${SHARED_LIB_PATH}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}
        COMMAND ${GO_EXECUTABLE} build ${GO_BUILD_MODE}
            -o ${SHARED_LIB_PATH}
            ${CMAKE_CURRENT_SOURCE_DIR}/src/luxfhe.go
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/luxfhe.go
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/..
        COMMENT "Building LuxFHE shared library"
    )
    
    add_custom_target(luxfhe_shared ALL DEPENDS ${SHARED_LIB_PATH})
    
    # Import the built library
    add_library(luxfhe SHARED IMPORTED GLOBAL)
    set_target_properties(luxfhe PROPERTIES
        IMPORTED_LOCATION ${SHARED_LIB_PATH}
        INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    add_dependencies(luxfhe luxfhe_shared)
endif()

# Build static library
if(LUXFHE_BUILD_STATIC)
    set(STATIC_LIB_NAME "libluxfhe${STATIC_LIB_EXT}")
    set(STATIC_LIB_PATH "${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/${STATIC_LIB_NAME}")
    
    add_custom_command(
        OUTPUT ${STATIC_LIB_PATH}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}
        COMMAND ${GO_EXECUTABLE} build -buildmode=c-archive
            -o ${STATIC_LIB_PATH}
            ${CMAKE_CURRENT_SOURCE_DIR}/src/luxfhe.go
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/luxfhe.go
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/..
        COMMENT "Building LuxFHE static library"
    )
    
    add_custom_target(luxfhe_static ALL DEPENDS ${STATIC_LIB_PATH})
    
    # Import the built library
    add_library(luxfhe_a STATIC IMPORTED GLOBAL)
    set_target_properties(luxfhe_a PROPERTIES
        IMPORTED_LOCATION ${STATIC_LIB_PATH}
        INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    add_dependencies(luxfhe_a luxfhe_static)
endif()

# Tests
if(LUXFHE_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Examples
if(LUXFHE_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# Installation
install(FILES include/luxfhe.h DESTINATION include)

if(LUXFHE_BUILD_SHARED)
    install(FILES ${SHARED_LIB_PATH} DESTINATION lib)
endif()

if(LUXFHE_BUILD_STATIC)
    install(FILES ${STATIC_LIB_PATH} DESTINATION lib)
endif()

# pkg-config file
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/luxfhe.pc.in
    ${CMAKE_CURRENT_BINARY_DIR}/luxfhe.pc
    @ONLY
)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/luxfhe.pc DESTINATION lib/pkgconfig)

# CMake config file
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/luxfhe-config-version.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/luxfhe-config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/luxfhe-config.cmake
    @ONLY
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/luxfhe-config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/luxfhe-config-version.cmake
    DESTINATION lib/cmake/luxfhe
)

# Print summary
message(STATUS "")
message(STATUS "LuxFHE Configuration:")
message(STATUS "  Version:       ${PROJECT_VERSION}")
message(STATUS "  Build shared:  ${LUXFHE_BUILD_SHARED}")
message(STATUS "  Build static:  ${LUXFHE_BUILD_STATIC}")
message(STATUS "  Build tests:   ${LUXFHE_BUILD_TESTS}")
message(STATUS "  Build examples: ${LUXFHE_BUILD_EXAMPLES}")
message(STATUS "")
