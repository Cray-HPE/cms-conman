# Dockerfile for cray-conman service
# Copyright 2018-2020 Hewlett Packard Enterprise Development LP

# Build will be where we build the go binary
FROM dtr.dev.cray.com/baseos/sles15sp1:sles15sp1 AS build
RUN set -eux \
    && zypper --non-interactive install go1.14

# Configure go env - installed as package but not quite configured
ENV GOPATH=/usr/local/golib
RUN export GOPATH=$GOPATH

# Copy in all the necessary files
COPY configure_conman.go $GOPATH/src/
COPY vendor/ $GOPATH/src/

# Build configure_conman
RUN set -ex && go build -v -i -o /app/configure_conman $GOPATH/src/configure_conman.go

### Final Stage ###
# Start with a fresh image so build tools are not included
FROM dtr.dev.cray.com/baseos/sles15sp1:sles15sp1

# Install conman application from package
RUN set -eux \
    && zypper --non-interactive install conman less vi openssh

# Copy in the needed files
COPY --from=build /app/configure_conman /app/
COPY conman.conf /app/conman_base.conf
COPY ssh-console /usr/bin

# Environment Variables -- Used by the HMS secure storage pkg
ENV VAULT_ADDR="http://cray-vault.vault:8200"
ENV VAULT_SKIP_VERIFY="true"

RUN echo 'alias ll="ls -l"' > ~/.bashrc
RUN echo 'alias vi="vim"' >> ~/.bashrc

ENTRYPOINT ["/app/configure_conman"]
