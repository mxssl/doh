FROM golang:1.21.5-alpine3.17 as builder

WORKDIR /app
COPY . .

RUN CGO_ENABLED=0 \
  go build -v -o doh

FROM alpine:3.19
COPY --from=builder /app/doh /usr/local/bin/doh
