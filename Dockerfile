# Lux FHE Server - Pure Go TFHE Implementation
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build server
RUN CGO_ENABLED=0 GOOS=linux go build -o fhe-server ./cmd/fhe-server/

# Runtime image
FROM alpine:3.19

RUN apk add --no-cache ca-certificates curl

WORKDIR /app

COPY --from=builder /app/fhe-server .

# Create data directory
RUN mkdir -p /app/data

EXPOSE 8448

ENTRYPOINT ["./fhe-server"]
CMD ["-addr", ":8448"]
