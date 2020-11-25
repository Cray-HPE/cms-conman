# Dockerfile for build HMS compcredentials code. Note this image can't be run as these are just packages in this repo.
# Copyright 2019 Cray Inc. All rights reserved.

# Build base just has the packages installed we need.
FROM golang:alpine as build-base

RUN set -ex \
    && apk add build-base

# Copy the files in for the next stages to use.
FROM build-base as base

COPY compCredentials.go compCredentials_test.go $GOPATH/src/stash.us.cray.com/HMS/hms-compcredentials/
COPY vendor $GOPATH/src/stash.us.cray.com/HMS/hms-compcredentials/vendor


# Now we can build.
FROM base

RUN set -ex \
    && go build -v stash.us.cray.com/HMS/hms-compcredentials/...
