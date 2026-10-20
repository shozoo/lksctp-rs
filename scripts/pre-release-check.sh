#!/bin/sh
set -eu

if [ "$(uname -s)" != Linux ]; then
    echo "Release checks require Linux with kernel SCTP support" >&2
    exit 1
fi

python3 -c 'import socket; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 132); s.close()'
cargo test --all-targets
cargo test --no-default-features
RUSTDOCFLAGS='-D warnings' cargo doc --no-deps
cargo clippy --all-targets -- -D warnings
cargo fmt --check
