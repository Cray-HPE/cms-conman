# Dockerfile for cray-conman service
# Copyright 2018-2021 Hewlett Packard Enterprise Development LP
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
#
# (MIT License)

# Build will be where we build the go binary
FROM arti.dev.cray.com/baseos-docker-master-local/sles15sp2:sles15sp2 AS build
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
FROM arti.dev.cray.com/baseos-docker-master-local/sles15sp2:sles15sp2

# Install conman application from package
RUN set -eux \
    && zypper --non-interactive install conman less vi openssh jq curl

# Copy in the needed files
COPY --from=build /app/configure_conman /app/
COPY conman.conf /app/conman_base.conf
COPY ssh-console /usr/bin
COPY console-ssh-keygen /app/console-ssh-keygen

# Environment Variables -- Used by the HMS secure storage pkg
ENV VAULT_ADDR="http://cray-vault.vault:8200"
ENV VAULT_SKIP_VERIFY="true"

RUN echo 'alias ll="ls -l"' > ~/.bashrc
RUN echo 'alias vi="vim"' >> ~/.bashrc

ENTRYPOINT ["/app/configure_conman"]
