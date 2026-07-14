#!/bin/bash
# Setup script referenced from Dockerfile
# This tests that COPY references are detected and scanned

echo "Running setup..."

# SHADOW: cargo install in setup script
cargo install cargo-audit

echo "Setup complete!"
