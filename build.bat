@echo off
setlocal

echo Cleaning up bin directory...
if exist bin (
    rmdir /s /q bin
)
mkdir bin\windows
mkdir bin\linux

echo ==========================
echo Building for Windows (amd64)...
set GOOS=windows
set GOARCH=amd64
go build -o bin/windows/client.exe ./cmd/client/main.go
if %errorlevel% neq 0 exit /b %errorlevel%
go build -o bin/windows/server.exe ./cmd/server/main.go
if %errorlevel% neq 0 exit /b %errorlevel%
go build -o bin/windows/test_udp.exe ./cmd/test_udp/main.go
if %errorlevel% neq 0 exit /b %errorlevel%
go build -o bin/windows/stats.exe ./cmd/stats/main.go
if %errorlevel% neq 0 exit /b %errorlevel%
echo [OK] Windows binaries created in bin\windows

echo ==========================
echo Building for Linux (amd64)...
set GOOS=linux
set GOARCH=amd64
go build -o bin/linux/client ./cmd/client/main.go
if %errorlevel% neq 0 exit /b %errorlevel%
go build -o bin/linux/server ./cmd/server/main.go
if %errorlevel% neq 0 exit /b %errorlevel%
go build -o bin/linux/stats ./cmd/stats/main.go
if %errorlevel% neq 0 exit /b %errorlevel%
echo [OK] Linux binaries created in bin\linux

echo ==========================
echo Build Complete.
endlocal
pause
