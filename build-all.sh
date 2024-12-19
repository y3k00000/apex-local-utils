#!/bin/sh

OS="$1"
ARCH="$2"
DEBUG="$3"
if [ -z "$OS" ]; then
    OS="windows"
fi
if [ -z "$ARCH" ]; then
    ARCH="amd64"
fi
if [ -z "$DEBUG" ]; then
    DEBUG="false"
fi
GOBUILDER="garble"
if [ "$DEBUG" = "debug" ]; then
    GOBUILDER="go"
fi  

printf "Building for OS: %s, ARCH: %s, GOBUILDER=%s\n" "$OS" "$ARCH" "$GOBUILDER"

SUFFIX=""
if [ "$OS" = "windows" ]; then
    SUFFIX=".exe"
fi

GOOS=$OS GOARCH=$ARCH "$GOBUILDER" build -o "apex-privatebox-registertool-$ARCH$SUFFIX" ./apex-privatebox-registertool
GOOS=$OS GOARCH=$ARCH "$GOBUILDER" build -o "apex-privatebox-setuptool-$ARCH$SUFFIX" ./apex-privatebox-setuptool
GOOS=$OS GOARCH=$ARCH "$GOBUILDER" build -o "apex-privatebox-cryptkey-$ARCH$SUFFIX" ./apex-privatebox-cryptkey