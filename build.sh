#!/bin/bash

echo "Cleaning up bin directory..."
rm -rf bin
mkdir -p bin/windows
mkdir -p bin/linux

echo "=========================="
echo "Building for Linux (amd64)..."
export GOOS=linux
export GOARCH=amd64
go build -o bin/linux/client ./cmd/client/main.go
go build -o bin/linux/server ./cmd/server/main.go
echo "[OK] Linux binaries created in bin/linux"

echo "=========================="
echo "Building for Windows (amd64)..."
export GOOS=windows
export GOARCH=amd64
go build -o bin/windows/client.exe ./cmd/client/main.go
go build -o bin/windows/server.exe ./cmd/server/main.go
echo "[OK] Windows binaries created in bin/windows"

echo "=========================="
echo "Build Complete."
