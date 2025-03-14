#!/bin/bash

set -e  # Exit on error

BIN="bin"
TAGS="netgo"
STATIC_LDFLAGS='-extldflags "-static"'

# Ensure the bin directory exists
mkdir -p $BIN

echo "Building my_scion-bwtestclient with static linking..."
CGO_ENABLED=0 go build -tags="$TAGS" -ldflags="$STATIC_LDFLAGS" -o "$BIN/my_scion-bwtestclient" ./bwtester/bwtestclient/

echo "Building my_scion-bwtestserver with static linking..."
CGO_ENABLED=0 go build -tags="$TAGS" -ldflags="$STATIC_LDFLAGS" -o "$BIN/my_scion-bwtestserver" ./bwtester/bwtestserver/

echo "Build complete. Binaries are in the '$BIN' directory."

# Verify if the binary is truly static
echo "Checking if binaries are statically linked..."
ldd "$BIN/my_scion-bwtestclient" || echo "Binary is fully static!"
ldd "$BIN/my_scion-bwtestserver" || echo "Binary is fully static!"
