# doh

Simple DNS over HTTPS cli client for cloudflare

## Install

### Linux

```bash
wget https://github.com/mxssl/doh/releases/download/v0.0.12/doh_linux_amd64.tar.gz
tar zvxf doh_linux_amd64.tar.gz
mv doh /usr/local/bin/doh
chmod +x /usr/local/bin/doh
rm doh_linux_amd64.tar.gz
```

### MacOS amd64

```bash
wget https://github.com/mxssl/doh/releases/download/v0.0.12/doh_darwin_amd64.tar.gz
tar zvxf doh_darwin_amd64.tar.gz
mv doh /usr/local/bin/doh
chmod +x /usr/local/bin/doh
rm doh_darwin_amd64.tar.gz
```

### MacOS arm64 (Apple Silicon)

```bash
wget https://github.com/mxssl/doh/releases/download/v0.0.12/doh_darwin_arm64.tar.gz
tar zvxf doh_darwin_arm64.tar.gz
mv doh /usr/local/bin/doh
chmod +x /usr/local/bin/doh
rm doh_darwin_arm64.tar.gz
```

### Golang

```bash
go install github.com/mxssl/doh@latest
```

### Docker

```bash
docker pull mxssl/doh:v0.0.12
docker container run --rm mxssl/doh:v0.0.12 doh a google.com
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
