FROM golang:1.24.6-alpine3.22 as builder

WORKDIR /app
COPY . .

RUN CGO_ENABLED=0 \
  go build -v -o doh

FROM alpine:3.22
COPY --from=builder /app/doh /usr/local/bin/doh
