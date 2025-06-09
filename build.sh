#!/bin/bash
echo "Updating dependencies..."
go mod tidy

if [ $? -ne 0 ]; then
    echo "Failed to download dependencies."
    exit 1
fi

echo "Building IPv6 proxy server..."
go build -o ipv6-proxy

if [ $? -eq 0 ]; then
    echo "Build successful! Binary created: ipv6-proxy"
    chmod +x ipv6-proxy
else
    echo "Build failed. Please check for errors."
    exit 1
fi 
