#!/usr/bin/env bash

# Build the build base image
docker build -t cray/hms-securestorage-build-base -f Dockerfile.build-base .

docker build -t cray/hms-securestorage-testing -f Dockerfile.testing .
