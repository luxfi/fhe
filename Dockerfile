# Lux FHE - Multi-target Dockerfile
# Builds: server (pure-go), gateway, worker

FROM golang:1.23-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Enable toolchain auto-download for newer Go versions
ENV GOTOOLCHAIN=auto

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build binaries (pure Go, no CGO)
RUN CGO_ENABLED=0 GOOS=linux go build -o /bin/fhe-gateway ./cmd/fhe-gateway/
RUN CGO_ENABLED=0 GOOS=linux go build -o /bin/fhe-worker ./cmd/fhe-worker/

# Build pure-go server (creates standalone server without C acceleration)
RUN CGO_ENABLED=0 GOOS=linux go build -tags purgo -o /bin/fhe-server ./server/standalone/

# =============================================================================
# Server image (pure Go implementation)
# =============================================================================
FROM alpine:3.19 AS server

RUN apk add --no-cache ca-certificates curl

WORKDIR /app

COPY --from=builder /bin/fhe-server .

RUN mkdir -p /app/data

EXPOSE 8448

ENTRYPOINT ["./fhe-server"]
CMD ["-addr", ":8448"]

# =============================================================================
# Gateway image
# =============================================================================
FROM alpine:3.19 AS gateway

RUN apk add --no-cache ca-certificates curl

WORKDIR /app

COPY --from=builder /bin/fhe-gateway .

RUN mkdir -p /app/data

EXPOSE 8080

ENTRYPOINT ["./fhe-gateway"]
CMD ["-http", ":8080"]

# =============================================================================
# Worker image
# =============================================================================
FROM alpine:3.19 AS worker

RUN apk add --no-cache ca-certificates curl

WORKDIR /app

COPY --from=builder /bin/fhe-worker .

RUN mkdir -p /app/data

EXPOSE 9090

ENTRYPOINT ["./fhe-worker"]
CMD ["-workers", "4"]
