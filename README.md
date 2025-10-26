# doh

Simple DNS over HTTPS cli client for cloudflare

## Install

### Linux amd64

```bash
curl -LO https://github.com/mxssl/doh/releases/download/v0.0.15/doh_linux_amd64.tar.gz
tar zvxf doh_linux_amd64.tar.gz
sudo mv doh /usr/local/bin/doh
rm doh_linux_amd64.tar.gz
```

### Linux arm64

```bash
curl -LO https://github.com/mxssl/doh/releases/download/v0.0.15/doh_linux_arm64.tar.gz
tar zvxf doh_linux_arm64.tar.gz
sudo mv doh /usr/local/bin/doh
rm doh_linux_arm64.tar.gz
```

### MacOS arm64 (Apple Silicon)

```bash
curl -LO https://github.com/mxssl/doh/releases/download/v0.0.15/doh_darwin_arm64.tar.gz
tar zvxf doh_darwin_arm64.tar.gz
sudo mv doh /usr/local/bin/doh
rm doh_darwin_arm64.tar.gz
```

### Golang

```bash
go install github.com/mxssl/doh@latest
```

### Docker

```bash
docker pull mxssl/doh:v0.0.15
docker container run --rm mxssl/doh:v0.0.15 a google.com
```

## Usage

```bash
doh [flags] [query type] [domain name]
```

### Flags

- `--whois` - Perform WHOIS lookup for IP addresses (A and AAAA records)

## Examples

### Basic DNS query (without WHOIS)

```bash
$ doh a google.com
name: google.com
type: 1
ttl: 291
data: 142.250.200.78
```

### DNS query with WHOIS lookup

```bash
$ doh a google.com --whois
name: google.com
type: 1
ttl: 291
data: 142.250.200.78
whois: Google LLC
```
