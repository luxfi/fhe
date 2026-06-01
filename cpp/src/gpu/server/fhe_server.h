// Copyright (C) 2024-2025 Lux Industries Inc.
// SPDX-License-Identifier: Apache-2.0
//
// High-Performance C++ FHE Server
// Benchmarking server for comparison with Go TFHE server

#pragma once

#include <http/http.h>
#include <http/HttpController.h>
#include <json/json.h>
#include <memory>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <chrono>

#ifdef WITH_CUDA
#include "../cuda/multi_gpu_manager.cuh"
#endif

namespace lux::fhe::server {

using namespace http;

//=============================================================================
// Server Configuration
//=============================================================================

struct ServerConfig {
    std::string host = "0.0.0.0";
    uint16_t port = 8080;
    int num_threads = 0;  // 0 = auto-detect
    int num_gpus = 8;     // Number of GPUs to use
    size_t pool_size_per_gpu = 8ULL * 1024 * 1024 * 1024;  // 8GB
    size_t key_cache_size = 16ULL * 1024 * 1024 * 1024;    // 16GB
    bool enable_work_stealing = true;
    bool enable_prefetch = true;
    int streams_per_gpu = 4;
    std::string log_level = "info";
};

//=============================================================================
// Key Management
//=============================================================================

struct PublicKeyInfo {
    std::string key_id;
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> serialized_bsk;  // Bootstrapping key
    std::vector<uint8_t> serialized_ksk;  // Key-switching key
    std::chrono::system_clock::time_point created_at;
    std::atomic<uint64_t> operations_count{0};
};

class KeyManager {
private:
    std::unordered_map<std::string, std::shared_ptr<PublicKeyInfo>> keys_;
    mutable std::mutex mutex_;
    
public:
    std::shared_ptr<PublicKeyInfo> getKey(const std::string& key_id) const;
    void registerKey(std::shared_ptr<PublicKeyInfo> key);
    void removeKey(const std::string& key_id);
    std::vector<std::string> listKeys() const;
    size_t keyCount() const;
};

//=============================================================================
// Evaluator Pool (like Go's sync.Pool)
//=============================================================================

template<typename T>
class ObjectPool {
private:
    std::vector<std::unique_ptr<T>> pool_;
    std::mutex mutex_;
    std::function<std::unique_ptr<T>()> factory_;
    
public:
    explicit ObjectPool(std::function<std::unique_ptr<T>()> factory, size_t initial_size = 4)
        : factory_(std::move(factory))
    {
        for (size_t i = 0; i < initial_size; i++) {
            pool_.push_back(factory_());
        }
    }
    
    std::unique_ptr<T> acquire() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (pool_.empty()) {
            return factory_();
        }
        auto obj = std::move(pool_.back());
        pool_.pop_back();
        return obj;
    }
    
    void release(std::unique_ptr<T> obj) {
        std::lock_guard<std::mutex> lock(mutex_);
        pool_.push_back(std::move(obj));
    }
    
    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return pool_.size();
    }
};

//=============================================================================
// FHE Evaluator Wrapper
//=============================================================================

class Evaluator {
private:
    std::string key_id_;
#ifdef WITH_CUDA
    gpu::cuda::PipelinedFHEOps* ops_;
#endif
    
public:
    explicit Evaluator(const std::string& key_id);
    ~Evaluator();
    
    // Basic operations
    std::vector<uint8_t> bootstrap(const std::vector<uint8_t>& ciphertext);
    std::vector<uint8_t> add(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);
    std::vector<uint8_t> mul(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);
    std::vector<uint8_t> sub(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);
    std::vector<uint8_t> neg(const std::vector<uint8_t>& a);
    
    // EVM uint256 operations (Kogge-Stone parallel carry)
    std::vector<uint8_t> addUint256(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);
    std::vector<uint8_t> mulUint256(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);
    std::vector<uint8_t> ltUint256(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);
    
    // Comparison
    std::vector<uint8_t> lt(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);
    std::vector<uint8_t> eq(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);
    
    // Bitwise
    std::vector<uint8_t> andOp(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);
    std::vector<uint8_t> orOp(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);
    std::vector<uint8_t> xorOp(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);
    std::vector<uint8_t> notOp(const std::vector<uint8_t>& a);
};

//=============================================================================
// Request/Response Types
//=============================================================================

struct EncryptRequest {
    std::string key_id;
    uint64_t value;
    int bit_width = 64;
};

struct DecryptRequest {
    std::string key_id;
    std::string ciphertext_b64;
};

struct EvaluateRequest {
    std::string key_id;
    std::string operation;  // "add", "mul", "sub", "lt", "eq", "and", "or", "xor", etc.
    std::vector<std::string> operands_b64;  // Base64-encoded ciphertexts
};

struct BatchEvaluateRequest {
    std::string key_id;
    std::vector<EvaluateRequest> operations;
};

struct ThresholdRequest {
    std::string key_id;
    int threshold;
    int total_parties;
    std::string session_id;
};

//=============================================================================
// HTTP Controllers
//=============================================================================

class HealthController : public HttpController<HealthController> {
public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(HealthController::health, "/health", Get);
    ADD_METHOD_TO(HealthController::ready, "/ready", Get);
    ADD_METHOD_TO(HealthController::stats, "/stats", Get);
    METHOD_LIST_END
    
    void health(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback);
    void ready(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback);
    void stats(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback);
};

class KeyController : public HttpController<KeyController> {
public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(KeyController::getPublicKey, "/publickey/{key_id}", Get);
    ADD_METHOD_TO(KeyController::listKeys, "/publickey", Get);
    ADD_METHOD_TO(KeyController::generateKey, "/publickey/generate", Post);
    METHOD_LIST_END
    
    void getPublicKey(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback, const std::string& key_id);
    void listKeys(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback);
    void generateKey(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback);
};

class EncryptController : public HttpController<EncryptController> {
public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(EncryptController::encrypt, "/encrypt", Post);
    ADD_METHOD_TO(EncryptController::encryptBatch, "/encrypt/batch", Post);
    METHOD_LIST_END
    
    void encrypt(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback);
    void encryptBatch(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback);
};

class DecryptController : public HttpController<DecryptController> {
public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(DecryptController::decrypt, "/decrypt", Post);
    ADD_METHOD_TO(DecryptController::decryptBatch, "/decrypt/batch", Post);
    METHOD_LIST_END
    
    void decrypt(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback);
    void decryptBatch(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback);
};

class EvaluateController : public HttpController<EvaluateController> {
public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(EvaluateController::evaluate, "/evaluate", Post);
    ADD_METHOD_TO(EvaluateController::evaluateBatch, "/evaluate/batch", Post);
    ADD_METHOD_TO(EvaluateController::bootstrap, "/bootstrap", Post);
    METHOD_LIST_END
    
    void evaluate(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback);
    void evaluateBatch(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback);
    void bootstrap(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback);
};

class ThresholdController : public HttpController<ThresholdController> {
public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(ThresholdController::initSession, "/threshold/init", Post);
    ADD_METHOD_TO(ThresholdController::addShare, "/threshold/share/{session_id}", Post);
    ADD_METHOD_TO(ThresholdController::combine, "/threshold/combine/{session_id}", Post);
    METHOD_LIST_END
    
    void initSession(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback);
    void addShare(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback, const std::string& session_id);
    void combine(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback, const std::string& session_id);
};

//=============================================================================
// Server Statistics
//=============================================================================

struct ServerStats {
    std::atomic<uint64_t> total_requests{0};
    std::atomic<uint64_t> encrypt_requests{0};
    std::atomic<uint64_t> decrypt_requests{0};
    std::atomic<uint64_t> evaluate_requests{0};
    std::atomic<uint64_t> bootstrap_requests{0};
    std::atomic<uint64_t> errors{0};
    std::atomic<uint64_t> total_latency_us{0};
    std::chrono::system_clock::time_point start_time;
    
    double avgLatencyUs() const {
        uint64_t total = total_requests.load();
        return total > 0 ? (double)total_latency_us.load() / total : 0.0;
    }
    
    double requestsPerSecond() const {
        auto now = std::chrono::system_clock::now();
        auto elapsed = std::chrono::duration<double>(now - start_time).count();
        return elapsed > 0 ? total_requests.load() / elapsed : 0.0;
    }
};

//=============================================================================
// Main Server Class
//=============================================================================

class FHEServer {
private:
    ServerConfig config_;
    std::unique_ptr<KeyManager> key_manager_;
    std::unique_ptr<ObjectPool<Evaluator>> evaluator_pool_;
    ServerStats stats_;
    
#ifdef WITH_CUDA
    std::unique_ptr<gpu::cuda::MultiGPUFHEPipeline> pipeline_;
#endif
    
    bool initialized_ = false;
    
public:
    explicit FHEServer(const ServerConfig& config = ServerConfig{});
    ~FHEServer();
    
    // Initialize GPU pipeline and key manager
    bool initialize();
    
    // Start the HTTP server (blocking)
    void run();
    
    // Start the HTTP server (non-blocking)
    void start();
    
    // Stop the server
    void stop();
    
    // Accessors
    KeyManager& keyManager() { return *key_manager_; }
    ObjectPool<Evaluator>& evaluatorPool() { return *evaluator_pool_; }
    ServerStats& stats() { return stats_; }
    
#ifdef WITH_CUDA
    gpu::cuda::MultiGPUFHEPipeline& pipeline() { return *pipeline_; }
#endif
    
    // Singleton for controller access
    static FHEServer* instance();
    
private:
    static FHEServer* instance_;
};

//=============================================================================
// Utilities
//=============================================================================

namespace util {

// Base64 encoding/decoding
std::string base64Encode(const std::vector<uint8_t>& data);
std::vector<uint8_t> base64Decode(const std::string& encoded);

// JSON helpers
Json::Value toJson(const ServerStats& stats);
Json::Value toJson(const PublicKeyInfo& key);

// Parse requests from JSON
EncryptRequest parseEncryptRequest(const Json::Value& json);
DecryptRequest parseDecryptRequest(const Json::Value& json);
EvaluateRequest parseEvaluateRequest(const Json::Value& json);

// Timing
class Timer {
    std::chrono::high_resolution_clock::time_point start_;
public:
    Timer() : start_(std::chrono::high_resolution_clock::now()) {}
    
    double elapsedUs() const {
        auto now = std::chrono::high_resolution_clock::now();
        return std::chrono::duration<double, std::micro>(now - start_).count();
    }
    
    double elapsedMs() const { return elapsedUs() / 1000.0; }
    double elapsedSec() const { return elapsedUs() / 1000000.0; }
};

}  // namespace util

}  // namespace lux::fhe::server
