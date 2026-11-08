# SAND Egress and Local DNS Proxy

This guide covers the opt-in SAND egress proxy and the local UDP DNS proxy. The DNS proxy runs in the same long-lived process as a tunnel and sends DNS wire messages to Google DoH.

## SAND egress proxy

SAND egress is disabled by default. Enable it with `SAND_EGRESS_TUNNEL_ENABLED=1` and provide an HTTP proxy in `SAND_EGRESS_TUNNEL_PROXY_ADDR`:

```sh
SAND_EGRESS_TUNNEL_ENABLED=1 \
SAND_EGRESS_TUNNEL_PROXY_ADDR='127.0.0.1:8791' \
cloudflared tunnel run <TUNNEL>
```

The proxy value may be a bare `host:port` or an HTTP URL with optional userinfo and port:

```sh
SAND_EGRESS_TUNNEL_PROXY_ADDR='http://user:password@proxy.example:8080'
SAND_EGRESS_TUNNEL_PROXY_ADDR='http://user:password@proxy.example' # port defaults to 80
```

Only plain HTTP proxy URLs are accepted; paths, queries, and fragments are rejected. URL-escape reserved characters in credentials. Userinfo is sent as Basic proxy authentication over the client-to-proxy HTTP connection. That link is unencrypted: use credentials only on a trusted network. Cloudflared redacts the proxy environment value in its environment log.

When enabled, cloudflared:

- Sends selected startup DNS lookups, including feature TXT lookups, to `https://dns.google/resolve` through the proxy.
- Resolves edge addresses through the same DoH resolver and connects to edge TCP addresses using HTTP CONNECT through the proxy.
- Forces the tunnel transport to HTTP/2, even if `--protocol quic` is supplied. Startup prechecks skip QUIC and probe HTTP/2 through the proxy. The separate `api.cloudflare.com:443` management probe remains direct.

A hostname-valued proxy must be resolved before the proxy can be reached; that bootstrap lookup uses the OS resolver. Use a literal proxy IP to avoid it. Missing or malformed proxy configuration is a startup error when SAND egress is enabled. The enable variable must equal exactly `1`.

## Local DNS proxy

Enable the local UDP DNS proxy when starting a tunnel:

```sh
cloudflared tunnel run --dns-proxy <TUNNEL>
```

It listens on UDP port 53 at `127.0.0.1` by default. Supply another loopback IP to change the bind address:

```sh
cloudflared tunnel run --dns-proxy 127.0.0.2 <TUNNEL>
```

Only loopback IP addresses are accepted. UDP port 53 must be available, and the process must have permission to bind it. The proxy forwards DNS wire messages to `https://dns.google/dns-query` using DoH; an upstream DoH error is returned to the client as `SERVFAIL`.

If `SAND_EGRESS_TUNNEL_PROXY_ADDR` is configured, DNS-proxy DoH requests use that HTTP proxy, including when SAND egress is otherwise disabled. When SAND egress is enabled, the DNS proxy reuses the same DoH client as startup DNS lookups. If no proxy address is configured, DNS-proxy DoH connects directly; cloudflared does not implicitly use `HTTP_PROXY` or `HTTPS_PROXY` for these requests.
