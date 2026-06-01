# Copyright (C) 2024-2025 Lux Industries Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Lux FHE GPU Module - MLX Backend (Metal/CUDA/CPU via JIT)
#
# MLX handles all GPU backends:
# - Apple Silicon: Native Metal
# - NVIDIA: CUDA (JIT compiled from Metal)
# - CPU: Fallback

cmake_minimum_required(VERSION 3.18)
project(fhe_gpu LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Options
option(WITH_MLX "Enable MLX GPU backend" ON)
option(BUILD_SERVER "Build FHE benchmark server" ON)
option(BUILD_SHARED_LIBS "Build shared libraries" OFF)

#=============================================================================
# MLX Setup - Single GPU Backend for All Platforms
#=============================================================================
if(WITH_MLX)
    # MLX backend is in core - just add the subdirectory
    set(MLX_BACKEND_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../core/lib/math/hal/mlx")

    if(EXISTS "${MLX_BACKEND_DIR}/CMakeLists.txt")
        add_subdirectory(${MLX_BACKEND_DIR} mlx_backend)
        set(FHE_GPU_BACKEND FHEmlx)
        message(STATUS "MLX GPU backend: enabled")
    else()
        message(WARNING "MLX backend not found at ${MLX_BACKEND_DIR}")
        set(WITH_MLX OFF)
    endif()
endif()

#=============================================================================
# GPU Primes and Twiddle Tables Library
#=============================================================================
add_library(fhe_gpu_primes STATIC
    src/gpu_primes.cpp
    src/twiddle_tables.cpp
)
target_include_directories(fhe_gpu_primes PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../core/include
)
target_compile_features(fhe_gpu_primes PUBLIC cxx_std_17)

#=============================================================================
# Common Interface Library
#=============================================================================
add_library(fhe_gpu INTERFACE)
target_include_directories(fhe_gpu INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../core/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../core/lib
)
target_link_libraries(fhe_gpu INTERFACE fhe_gpu_primes)

if(WITH_MLX AND TARGET ${FHE_GPU_BACKEND})
    # FHEmlx is an OBJECT library - need to link both objects and its dependencies
    target_link_libraries(fhe_gpu INTERFACE
        $<TARGET_OBJECTS:${FHE_GPU_BACKEND}>
        $<TARGET_PROPERTY:${FHE_GPU_BACKEND},LINK_LIBRARIES>
    )
    # Propagate include directories from the object library
    target_include_directories(fhe_gpu INTERFACE
        $<TARGET_PROPERTY:${FHE_GPU_BACKEND},INCLUDE_DIRECTORIES>
    )
    target_compile_definitions(fhe_gpu INTERFACE WITH_MLX)
endif()

#=============================================================================
# FHE Benchmark Server
#=============================================================================
if(BUILD_SERVER)
    set(DROGON_DIR "/Users/z/work/luxcpp/http")
    set(DROGON_BUILD_DIR "${DROGON_DIR}/build")

    if(EXISTS "${DROGON_BUILD_DIR}/libhttp.a")
        message(STATUS "Found pre-built Drogon at ${DROGON_BUILD_DIR}")

        add_library(drogon STATIC IMPORTED)
        set_target_properties(drogon PROPERTIES
            IMPORTED_LOCATION "${DROGON_BUILD_DIR}/libhttp.a"
            INTERFACE_INCLUDE_DIRECTORIES "${DROGON_DIR}/lib/inc;${DROGON_DIR}/orm_lib/inc;${DROGON_DIR}/trantor"
        )

        add_library(trantor STATIC IMPORTED)
        set_target_properties(trantor PROPERTIES
            IMPORTED_LOCATION "${DROGON_BUILD_DIR}/trantor/libtrantor.a"
        )

        set(Drogon_FOUND TRUE)
    else()
        find_package(Drogon QUIET)
    endif()

    if(Drogon_FOUND OR TARGET drogon)
        add_executable(fhe_server
            server/main.cpp
            server/fhe_server.cpp
        )

        target_include_directories(fhe_server PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}
            ${CMAKE_CURRENT_SOURCE_DIR}/server
            ${DROGON_DIR}/lib/inc
            ${DROGON_DIR}/trantor
            ${DROGON_DIR}/nosql_lib/redis/inc
            ${DROGON_DIR}/orm_lib/inc
            ${DROGON_BUILD_DIR}/exports
            ${DROGON_BUILD_DIR}/trantor/exports
        )

        if(TARGET drogon)
            target_link_libraries(fhe_server PRIVATE drogon trantor)
            find_package(OpenSSL REQUIRED)
            find_package(ZLIB REQUIRED)
            find_package(PkgConfig REQUIRED)
            pkg_check_modules(JSONCPP REQUIRED jsoncpp)
            target_include_directories(fhe_server PRIVATE ${JSONCPP_INCLUDE_DIRS})
            target_link_directories(fhe_server PRIVATE ${JSONCPP_LIBRARY_DIRS})
            target_link_libraries(fhe_server PRIVATE
                OpenSSL::SSL OpenSSL::Crypto
                ZLIB::ZLIB
                ${JSONCPP_LIBRARIES}
                "-framework Foundation"
                "-framework Security"
            )
        else()
            target_link_libraries(fhe_server PRIVATE Drogon::Drogon)
        endif()

        target_link_libraries(fhe_server PRIVATE fhe_gpu)
        message(STATUS "Building FHE benchmark server")
    else()
        message(WARNING "Drogon not found, skipping server build")
    endif()
endif()

#=============================================================================
# Benchmarks
#=============================================================================
add_executable(fhe_benchmark
    benchmarks/benchmark_main.cpp
)
target_link_libraries(fhe_benchmark PRIVATE fhe_gpu)

#=============================================================================
# Tests
#=============================================================================
enable_testing()

add_executable(test_gpu
    tests/test_multi_gpu.cpp
)
target_link_libraries(test_gpu PRIVATE fhe_gpu)
add_test(NAME GPUTest COMMAND test_gpu)

add_executable(test_gpu_primes
    tests/test_gpu_primes.cpp
)
target_link_libraries(test_gpu_primes PRIVATE fhe_gpu_primes)
add_test(NAME GPUPrimesTest COMMAND test_gpu_primes)

#=============================================================================
# Install
#=============================================================================
install(TARGETS fhe_gpu
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)

if(BUILD_SERVER AND TARGET fhe_server)
    install(TARGETS fhe_server
        RUNTIME DESTINATION bin
    )
endif()

#=============================================================================
# Summary
#=============================================================================
message(STATUS "")
message(STATUS "Lux FHE GPU Module:")
message(STATUS "  Backend: MLX (Metal/CUDA/CPU)")
message(STATUS "  MLX Enabled: ${WITH_MLX}")
message(STATUS "  Server: ${BUILD_SERVER}")
message(STATUS "")
