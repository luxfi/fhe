# LuxNext FHE - CUDA/Multi-GPU Backend (Proprietary)
#
# This module provides NVIDIA GPU acceleration for FHE operations.
# Requires: CUDA Toolkit 12.0+, cuBLAS, cuFFT
# Supports: H100, H200, HGX systems, multi-GPU configurations

cmake_minimum_required(VERSION 3.18)
project(LuxNextFHE CUDA CXX)

option(WITH_MULTI_GPU "Enable multi-GPU support (8x H200, HGX)" ON)
option(WITH_NCCL "Enable NCCL for multi-GPU communication" ON)
option(WITH_CUTLASS "Enable CUTLASS for optimized matrix ops" ON)

# Find CUDA
find_package(CUDAToolkit 12.0 REQUIRED)

# CUDA Architecture (H100/H200 = sm_90)
set(CMAKE_CUDA_ARCHITECTURES "80;86;89;90")

# Source files
file(GLOB_RECURSE CUDA_SOURCES
    src/core/lib/math/hal/cuda/*.cu
    src/core/lib/math/hal/cuda/*.cpp
    src/mlx/kernels/cuda/*.cu       # FHE CUDA kernels (NTT, bootstrap, EVM256)
    src/gpu/*.cpp
    src/gpu/*.cu
)

# Include directories
include_directories(
    src/core/include
    src/gpu/include
)

# Create CUDA library
add_library(FHEcuda SHARED ${CUDA_SOURCES})
target_link_libraries(FHEcuda
    CUDA::cudart
    CUDA::cublas
    CUDA::cufft
)

if(WITH_NCCL)
    find_package(NCCL REQUIRED)
    target_link_libraries(FHEcuda NCCL::NCCL)
    target_compile_definitions(FHEcuda PRIVATE WITH_NCCL)
endif()

if(WITH_CUTLASS)
    target_compile_definitions(FHEcuda PRIVATE WITH_CUTLASS)
endif()

if(WITH_MULTI_GPU)
    target_compile_definitions(FHEcuda PRIVATE WITH_MULTI_GPU)
endif()

message(STATUS "LuxNext FHE CUDA Backend configured")
message(STATUS "  Multi-GPU: ${WITH_MULTI_GPU}")
message(STATUS "  NCCL: ${WITH_NCCL}")
message(STATUS "  CUTLASS: ${WITH_CUTLASS}")
