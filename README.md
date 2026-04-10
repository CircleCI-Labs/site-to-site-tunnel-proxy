# site-to-site-tunnel-proxy - EXPERIMENTAL

HTTP CONNECT proxy that routes CI executor traffic through TLS tunnel endpoints with optional mTLS client certificates.

The proxy has two modes:

- `serve` runs an HTTP CONNECT proxy server that CI jobs use via `HTTPS_PROXY`
- `connect` runs in stdio mode for use as an SSH `ProxyCommand`

Both modes may present an mTLS client certificate on the outer TLS connection to the tunnel endpoint. The inner TLS session (between the CI job and the destination service) passes through untouched.

## Usage

### serve

Start the proxy server. CI jobs set `HTTPS_PROXY=http://127.0.0.1:4140` to route HTTPS traffic through it.

```
tunnel-proxy serve \
  --cert /tmp/client.crt \
  --key /tmp/client.key \
  --tunnel gh.acmecorp.dev=vcs.example.com \
  --tunnel gh.acmecorp.dev:22=vcs-ssh.example.com:443
```

The `--tunnel` flag maps internal hostnames to tunnel domains. Port 443 on the right-hand side enables TLS with mTLS, if certificats are specified.

### connect

Pipe stdin/stdout through a tunnel connection. Used as an SSH `ProxyCommand` for git-over-SSH.

```
tunnel-proxy connect \
  --cert /tmp/client.crt \
  --key /tmp/client.key \
  --tunnel gh.acmecorp.dev:22=vcs-ssh.example.com:443 \
  ghe.acmecorp.dev:22
```

In a CI job, set:

```
GIT_SSH_COMMAND="ssh -o ProxyCommand='tunnel-proxy connect --cert ... --key ... --tunnel ... %h:%p'"
```

## Building

```
./do build        # build for current platform
./do build-all    # cross-compile for linux/{amd64,arm64}, darwin/{amd64,arm64}, windows/amd64
./do test         # run tests
./do lint         # run golangci-lint
./do version      # print version string
```

Binaries are written to `target/bin/`. Version is injected via ldflags from `CIRCLE_BUILD_NUM` and the git short SHA.

## Testing

```
./do test
```

