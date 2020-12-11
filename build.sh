#!/usr/bin/env bash

cargo check &&
    cargo build --release &&
    cargo run -- --help &&
    cargo test
