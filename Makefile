# TFHE Makefile
# Production-ready build system for multi-platform SDK

.PHONY: all build test bench clean profile c python wasm install help

# Default target
all: build test

# Build all packages
build:
	go build ./...

# Run all tests
test:
	go test -v ./...

# Run benchmarks
bench:
	go test -bench=. -benchmem ./...

# Run benchmarks with count for statistical significance
bench-count:
	go test -bench=. -benchmem -count=5 ./... | tee bench.txt

# Clean build artifacts
clean:
	rm -rf c/build python/dist python/build python/*.egg-info
	rm -f cpu.prof mem.prof block.prof mutex.prof trace.out
	rm -f profile

# Profile targets
profile: profile-build
	./profile -cpu=cpu.prof -mem=mem.prof -iterations=100 -op=all

profile-build:
	go build -tags profile -o profile ./cmd/profile

profile-cpu: profile-build
	./profile -cpu=cpu.prof -iterations=1000 -op=gates
	go tool pprof -http=:8080 cpu.prof

profile-mem: profile-build
	./profile -mem=mem.prof -iterations=100 -op=keygen
	go tool pprof -http=:8080 mem.prof

# C/C++ bindings
c:
	cd c && mkdir -p build && cd build && cmake .. && make

c-test: c
	cd c/build && ctest --output-on-failure

c-install: c
	cd c/build && make install

c-clean:
	rm -rf c/build

# Python bindings
python: c
	cd python && pip install -e .

python-test: python
	cd python && python -m pytest tests/

python-build: c
	cd python && pip wheel . -w dist/

python-clean:
	rm -rf python/dist python/build python/*.egg-info

# WASM bindings
wasm:
	cd ../tfhe-wasm && make wasm

wasm-release:
	cd ../tfhe-wasm && make wasm-release

wasm-small:
	cd ../tfhe-wasm && make wasm-small

wasm-size:
	cd ../tfhe-wasm && make size

# Install development dependencies
deps:
	go mod download
	go mod tidy

# Format code
fmt:
	go fmt ./...
	gofmt -s -w .

# Lint code
lint:
	golangci-lint run

# Generate code coverage report
coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Run security analysis
security:
	gosec ./...

# Static analysis
vet:
	go vet ./...

# All quality checks
check: fmt vet lint security test

# Help
help:
	@echo "TFHE SDK Makefile"
	@echo ""
	@echo "Build targets:"
	@echo "  all          - Build and test (default)"
	@echo "  build        - Build all packages"
	@echo "  test         - Run all tests"
	@echo "  bench        - Run benchmarks"
	@echo "  clean        - Remove build artifacts"
	@echo ""
	@echo "Profile targets:"
	@echo "  profile      - Run full profiling suite"
	@echo "  profile-cpu  - CPU profiling with web UI"
	@echo "  profile-mem  - Memory profiling with web UI"
	@echo ""
	@echo "C/C++ bindings:"
	@echo "  c            - Build C bindings"
	@echo "  c-test       - Run C tests"
	@echo "  c-install    - Install C library"
	@echo ""
	@echo "Python bindings:"
	@echo "  python       - Install Python bindings (dev)"
	@echo "  python-test  - Run Python tests"
	@echo "  python-build - Build Python wheel"
	@echo ""
	@echo "WASM bindings:"
	@echo "  wasm         - Build WASM module"
	@echo "  wasm-release - Build optimized WASM"
	@echo "  wasm-small   - Build size-optimized WASM"
	@echo ""
	@echo "Quality checks:"
	@echo "  fmt          - Format code"
	@echo "  lint         - Run linter"
	@echo "  vet          - Run go vet"
	@echo "  coverage     - Generate coverage report"
	@echo "  check        - Run all quality checks"
