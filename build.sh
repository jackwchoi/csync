#!/usr/bin/env bash

cargo check &&
    cargo run -- --help &&
    cargo build --release &&
    cargo test --no-run
