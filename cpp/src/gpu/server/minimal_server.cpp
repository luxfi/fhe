// Copyright (C) 2024-2025 Lux Industries Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Minimal HTTP Server for FHE benchmarks - no framework dependencies

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <string>
#include <sstream>
#include <iostream>
#include <chrono>
#include <thread>
#include <vector>
#include <random>

#ifdef WITH_METAL
#include "../metal/metal_wrapper.mm"
#endif

namespace lux::fhe::server {

// Simple FHE simulation (placeholder - real impl would use Metal GPU)
class FHESimulator {
public:
    // Generate a random 16KB "public key"
    std::vector<uint8_t> generatePublicKey() {
        std::vector<uint8_t> key(16 * 1024);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        for (auto& b : key) b = dis(gen);
        return key;
    }
    
    // Simulate encryption - returns ~546KB ciphertext
    std::vector<uint8_t> encrypt(uint64_t value) {
        std::vector<uint8_t> ct(546 * 1024);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        for (auto& b : ct) b = dis(gen);
        return ct;
    }
    
    // Simulate decryption
    uint64_t decrypt(const std::vector<uint8_t>& ct) {
        return 42; // Placeholder
    }
    
    // Simulate homomorphic add
    std::vector<uint8_t> add(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
        std::vector<uint8_t> result(a.size());
        for (size_t i = 0; i < a.size(); i++) {
            result[i] = a[i] ^ b[i]; // XOR as placeholder
        }
        return result;
    }
};

static FHESimulator g_fhe;
static const char* HTTP_OK = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: keep-alive\r\n";
static const char* HTTP_404 = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: 9\r\n\r\nNot Found";

std::string base64Encode(const std::vector<uint8_t>& data) {
    static const char* chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    result.reserve(((data.size() + 2) / 3) * 4);
    
    for (size_t i = 0; i < data.size(); i += 3) {
        uint32_t n = data[i] << 16;
        if (i + 1 < data.size()) n |= data[i + 1] << 8;
        if (i + 2 < data.size()) n |= data[i + 2];
        
        result.push_back(chars[(n >> 18) & 0x3F]);
        result.push_back(chars[(n >> 12) & 0x3F]);
        result.push_back(i + 1 < data.size() ? chars[(n >> 6) & 0x3F] : '=');
        result.push_back(i + 2 < data.size() ? chars[n & 0x3F] : '=');
    }
    return result;
}

void handleRequest(int client_fd, const std::string& request) {
    auto start = std::chrono::high_resolution_clock::now();
    
    // Parse request line
    std::string method, path;
    std::istringstream iss(request);
    iss >> method >> path;
    
    std::string response;
    
    if (path == "/health") {
        response = std::string(HTTP_OK) + "Content-Length: 15\r\n\r\n{\"status\":\"ok\"}";
    }
    else if (path == "/publickey") {
        auto key = g_fhe.generatePublicKey();
        std::string encoded = base64Encode(key);
        std::string body = "{\"key_id\":\"default\",\"public_key\":\"" + encoded + "\"}";
        response = std::string(HTTP_OK) + "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
    }
    else if (path == "/encrypt" && method == "POST") {
        auto ct = g_fhe.encrypt(42);
        std::string encoded = base64Encode(ct);
        std::string body = "{\"ciphertext\":\"" + encoded + "\"}";
        response = std::string(HTTP_OK) + "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
    }
    else if (path == "/stats") {
        auto elapsed = std::chrono::high_resolution_clock::now() - start;
        auto us = std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();
        std::string body = "{\"latency_us\":" + std::to_string(us) + "}";
        response = std::string(HTTP_OK) + "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
    }
    else {
        response = HTTP_404;
    }
    
    send(client_fd, response.c_str(), response.size(), 0);
}

void runServer(int port) {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return;
    }
    
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(server_fd);
        return;
    }
    
    if (listen(server_fd, 128) < 0) {
        perror("listen");
        close(server_fd);
        return;
    }
    
    std::cout << "C++ FHE Server listening on port " << port << std::endl;
    
    while (true) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        
        if (client_fd < 0) {
            perror("accept");
            continue;
        }
        
        // Simple single-threaded for now
        char buffer[4096];
        ssize_t n = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
        if (n > 0) {
            buffer[n] = '\0';
            handleRequest(client_fd, std::string(buffer));
        }
        close(client_fd);
    }
    
    close(server_fd);
}

} // namespace lux::fhe::server

int main(int argc, char** argv) {
    int port = 8080;
    if (argc > 1) {
        port = std::atoi(argv[1]);
    }
    lux::fhe::server::runServer(port);
    return 0;
}
