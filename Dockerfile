FROM golang:1.19.4-alpine3.17 as builder

ENV GO111MODULE=on

WORKDIR /app
COPY . .

RUN CGO_ENABLED=0 \
  go build -v -o doh

FROM alpine:3.17
WORKDIR /
COPY --from=builder /app/dns /usr/local/bin/doh
