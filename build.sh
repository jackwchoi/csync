#!/usr/bin/env bash

set -x

cargo check &&
    cargo run -- --help &&
    cargo test --no-run &&
    cargo build --release
