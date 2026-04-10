#!/usr/bin/env bash
set -euo pipefail

_version="1.0.${CIRCLE_BUILD_NUM:-0}-$(git rev-parse --short HEAD 2>/dev/null || echo latest)"
date=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
ldflags="-s -w -X github.com/circleci/site-to-site-tunnel-proxy/cmd.Version=$_version -X github.com/circleci/site-to-site-tunnel-proxy/cmd.Date=$date"

help() {
    echo "Usage: ./do <command>"
    echo ""
    echo "Commands:"
    echo "  build       Build for current platform"
    echo "  build-all   Cross-compile for all platforms"
    echo "  test        Run tests"
    echo "  lint        Run golangci-lint"
    echo "  release     Upload binaries to S3"
    echo "  version     Print version"
}

build() {
    echo "Building tunnel-proxy $_version"
    mkdir -p target/bin
    go build -ldflags "$ldflags" -o target/bin/tunnel-proxy ./cmd/tunnel-proxy
}

build-all() {
    echo "Cross-compiling tunnel-proxy $_version"
    platforms=(
        "linux/amd64"
        "linux/arm64"
        "darwin/amd64"
        "darwin/arm64"
        "windows/amd64"
    )
    for platform in "${platforms[@]}"; do
        os="${platform%/*}"
        arch="${platform#*/}"
        output="target/bin/${os}/${arch}/tunnel-proxy"
        if [ "$os" = "windows" ]; then
            output="${output}.exe"
        fi
        echo "  ${os}/${arch}"
        mkdir -p "$(dirname "$output")"
        GOOS="$os" GOARCH="$arch" go build -ldflags "$ldflags" -o "$output" ./cmd/tunnel-proxy
    done
}

test() {
    echo "Running tests"
    gotestsum --format testdox -- -race -count=1 ./...
}

lint() {
    echo "Running linter"
    golangci-lint run ./...
}

release() {
    # TODO: Determine binary hosting location.
    echo "release not yet configured"
    exit 1
}

version() {
    echo "$_version"
}

command="${1:-help}"
shift || true

case "$command" in
    build|build-all|test|lint|release|version|help)
        "$command" "$@"
        ;;
    *)
        echo "Unknown command: $command"
        help
        exit 1
        ;;
esac
