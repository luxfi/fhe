// Copyright (C) 2024-2025 Lux Industries Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Lux FHE Server - Main Entry Point
// High-performance FHE server for benchmarking

#include "fhe_server.h"
#include <iostream>
#include <csignal>
#include <cstdlib>

using namespace lux::fhe::server;

// Global server pointer for signal handling
static FHEServer* g_server = nullptr;

void signalHandler(int signum) {
    std::cout << "\nReceived signal " << signum << ", shutting down..." << std::endl;
    if (g_server) {
        g_server->stop();
    }
    std::exit(0);
}

void printUsage(const char* prog) {
    std::cout << "Usage: " << prog << " [options]\n\n"
              << "Options:\n"
              << "  --host HOST       Bind address (default: 0.0.0.0)\n"
              << "  --port PORT       Listen port (default: 8080)\n"
              << "  --threads N       Worker threads (default: auto)\n"
              << "  --gpus N          Number of GPUs (default: 8)\n"
              << "  --pool-size GB    Memory pool per GPU in GB (default: 8)\n"
              << "  --key-cache GB    Key cache size in GB (default: 16)\n"
              << "  --no-work-steal   Disable work stealing\n"
              << "  --no-prefetch     Disable key prefetching\n"
              << "  --streams N       CUDA streams per GPU (default: 4)\n"
              << "  --help            Show this help\n"
              << std::endl;
}

int main(int argc, char** argv) {
    ServerConfig config;
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "--help" || arg == "-h") {
            printUsage(argv[0]);
            return 0;
        } else if (arg == "--host" && i + 1 < argc) {
            config.host = argv[++i];
        } else if (arg == "--port" && i + 1 < argc) {
            config.port = std::atoi(argv[++i]);
        } else if (arg == "--threads" && i + 1 < argc) {
            config.num_threads = std::atoi(argv[++i]);
        } else if (arg == "--gpus" && i + 1 < argc) {
            config.num_gpus = std::atoi(argv[++i]);
        } else if (arg == "--pool-size" && i + 1 < argc) {
            config.pool_size_per_gpu = static_cast<size_t>(std::atof(argv[++i]) * 1024 * 1024 * 1024);
        } else if (arg == "--key-cache" && i + 1 < argc) {
            config.key_cache_size = static_cast<size_t>(std::atof(argv[++i]) * 1024 * 1024 * 1024);
        } else if (arg == "--streams" && i + 1 < argc) {
            config.streams_per_gpu = std::atoi(argv[++i]);
        } else if (arg == "--no-work-steal") {
            config.enable_work_stealing = false;
        } else if (arg == "--no-prefetch") {
            config.enable_prefetch = false;
        } else {
            std::cerr << "Unknown option: " << arg << std::endl;
            printUsage(argv[0]);
            return 1;
        }
    }
    
    // Set up signal handlers
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);
    
    std::cout << R"(
╔═══════════════════════════════════════════════════════════════╗
║     _               _____ _   _ _____   ____                  ║
║    | |    _   ___  |  ___| | | | ____| / ___| ___ _ ____   __ ║
║    | |   | | | \ \/ / |_  | |_| |  _|  \___ \ / _ \ '__\ \ / / ║
║    | |___| |_| |>  <|  _| |  _  | |___  ___) |  __/ |   \ V /  ║
║    |_____|\__,_/_/\_\_|   |_| |_|_____||____/ \___|_|    \_/   ║
║                                                                ║
║    High-Performance FHE Server (C++)                          ║
║    Version 1.0.0                                               ║
╚═══════════════════════════════════════════════════════════════╝
)" << std::endl;
    
    std::cout << "Configuration:\n"
              << "  Host: " << config.host << "\n"
              << "  Port: " << config.port << "\n"
              << "  Threads: " << (config.num_threads ? std::to_string(config.num_threads) : "auto") << "\n"
              << "  GPUs: " << config.num_gpus << "\n"
              << "  Pool size per GPU: " << config.pool_size_per_gpu / (1024*1024*1024) << " GB\n"
              << "  Key cache size: " << config.key_cache_size / (1024*1024*1024) << " GB\n"
              << "  Work stealing: " << (config.enable_work_stealing ? "enabled" : "disabled") << "\n"
              << "  Key prefetch: " << (config.enable_prefetch ? "enabled" : "disabled") << "\n"
              << "  CUDA streams per GPU: " << config.streams_per_gpu << "\n"
              << std::endl;
    
    try {
        FHEServer server(config);
        g_server = &server;
        
        if (!server.initialize()) {
            std::cerr << "Failed to initialize server" << std::endl;
            return 1;
        }
        
        std::cout << "API Endpoints:\n"
                  << "  GET  /health              - Health check\n"
                  << "  GET  /ready               - Readiness probe\n"
                  << "  GET  /stats               - Server statistics\n"
                  << "  GET  /publickey           - List all keys\n"
                  << "  GET  /publickey/{id}      - Get specific key\n"
                  << "  POST /publickey/generate  - Generate new key\n"
                  << "  POST /encrypt             - Encrypt value\n"
                  << "  POST /encrypt/batch       - Batch encrypt\n"
                  << "  POST /decrypt             - Decrypt ciphertext\n"
                  << "  POST /decrypt/batch       - Batch decrypt\n"
                  << "  POST /evaluate            - Evaluate operation\n"
                  << "  POST /evaluate/batch      - Batch evaluate\n"
                  << "  POST /bootstrap           - Bootstrap ciphertext\n"
                  << "  POST /threshold/init      - Init threshold session\n"
                  << "  POST /threshold/share/{s} - Add share\n"
                  << "  POST /threshold/combine/s - Combine shares\n"
                  << std::endl;
        
        std::cout << "Server starting on http://" << config.host << ":" << config.port << std::endl;
        
        server.run();
        
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
