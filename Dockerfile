# syntax=docker/dockerfile:1

FROM golang:1.25.6-alpine3.22 AS builder

WORKDIR /app

# Copy go.mod and go.sum first to leverage Docker cache
COPY go.mod go.sum ./

# Download dependencies with cache mount for faster rebuilds
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

# Copy the rest of the source code
COPY . .

# Build the application with optimizations and cache mounts
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64 \
    go build -v \
    -ldflags="-s -w" \
    -trimpath \
    -o doh

FROM alpine:3.23

WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/doh /usr/local/bin/doh

# Add labels for metadata
LABEL org.opencontainers.image.title="doh" \
    org.opencontainers.image.description="DNS over HTTPS resolver" \
    org.opencontainers.image.source="https://github.com/mxssl/doh" \
    org.opencontainers.image.vendor="mxssl"

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/doh"]
