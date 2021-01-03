#!/usr/bin/env bash

set -x

cargo check &&
    cargo run -- --help &&
    cargo build --release &&
    cargo test --no-run
