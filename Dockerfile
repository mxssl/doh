FROM golang:1.19.0-alpine3.15 as builder

ENV GO111MODULE=on

WORKDIR /app
COPY . .

# Compile binary
RUN CGO_ENABLED=0 \
  go build -v -o doh"

# Copy compiled binary to clean Alpine Linux image
FROM alpine:3.16.2
WORKDIR /
COPY --from=builder /app/dns /usr/local/bin/doh
