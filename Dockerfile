# Lux FHE - Multi-target Dockerfile
# Builds: server, gateway, worker

FROM golang:1.23-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build all binaries
RUN CGO_ENABLED=0 GOOS=linux go build -o /bin/fhe-server ./cmd/fhe-server/
RUN CGO_ENABLED=0 GOOS=linux go build -o /bin/fhe-gateway ./cmd/fhe-gateway/
RUN CGO_ENABLED=0 GOOS=linux go build -o /bin/fhe-worker ./cmd/fhe-worker/

# =============================================================================
# Server image
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
CMD ["-metrics", ":9090", "-workers", "4"]
