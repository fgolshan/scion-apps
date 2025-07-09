#!/bin/bash

set -e  # Exit on error

BIN="bin"
TAGS="netgo"
STATIC_LDFLAGS='-extldflags "-static"'

# Ensure the bin directory exists
mkdir -p $BIN

echo "Building scion-bwtestclient with static linking..."
CGO_ENABLED=0 go build -tags="$TAGS" -ldflags="$STATIC_LDFLAGS" -o "$BIN/scion-bwtestclient" ./bwtester/bwtestclient/

echo "Building scion-bwtestserver with static linking..."
CGO_ENABLED=0 go build -tags="$TAGS" -ldflags="$STATIC_LDFLAGS" -o "$BIN/scion-bwtestserver" ./bwtester/bwtestserver/

echo "Build complete. Binaries are in the '$BIN' directory."

# Verify if the binary is truly static
echo "Checking if binaries are statically linked..."
ldd "$BIN/scion-bwtestclient" || echo "Binary is fully static!"
ldd "$BIN/scion-bwtestserver" || echo "Binary is fully static!"
