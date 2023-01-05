# doh

Simple DNS over HTTPS cli client for cloudflare

## Install

### Linux

```bash
wget https://github.com/mxssl/doh/releases/download/v0.0.3/doh_linux_x86_64.tar.gz
tar zvxf doh_linux_x86_64.tar.gz
mv doh /usr/local/bin/doh
chmod +x /usr/local/bin/doh
rm doh_linux_x86_64.tar.gz
```

### Golang

```bash
go install github.com/mxssl/doh@latest
```

### Docker

```bash
docker pull mxssl/doh:v0.0.3
docker container run --rm mxssl/doh:v0.0.3 doh a google.com
```

## Usage

```bash
doh [query type] [domain name]
```

## Example

```bash
$ doh a google.com
name: google.com
type: 1
ttl: 166
data: 142.250.180.238
```

## TODO

- ACE form encode (punycode)
