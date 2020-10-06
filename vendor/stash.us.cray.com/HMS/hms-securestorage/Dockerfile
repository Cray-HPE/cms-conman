# Copyright 2019 - 2020 Cray Inc. All rights reserved.

# Dockerfile for building HMS securestorage code. Note that this
# image can't be run as these are just packages in this repo.

# Build base just has the packages installed we need.
FROM dtr.dev.cray.com/baseos/golang:1.14-alpine3.11 as build-base

RUN set -ex \
    && apk update \
    && apk add build-base

# Copy the files in for the next stages to use.
FROM build-base as base

COPY *.go $GOPATH/src/stash.us.cray.com/HMS/hms-securestorage/
COPY vendor $GOPATH/src/stash.us.cray.com/HMS/hms-securestorage/vendor

# Now we can build.
FROM base

RUN set -ex \
    && go build -v stash.us.cray.com/HMS/hms-securestorage/...
