#!/bin/bash
# Test runner for MoltGrid SDK
# Builds the SDK and runs tests

set -e

echo "Building TypeScript SDK..."
npm run build:tsc

echo "Bundling with tsup..."
npm run build:bundle

echo "Running tests..."
node --test test/*.test.js

echo "All tests passed!"
