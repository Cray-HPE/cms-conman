#!/usr/bin/env bash

# Build the build base image
docker build -t cray/hms-compcredentials-build-base -f Dockerfile.build-base .

docker build -t cray/hms-compcredentials-testing -f Dockerfile.testing .
