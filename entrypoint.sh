#!/bin/sh -e
# Copyright 2019-2020, Cray Inc.
stdbuf -o 0 -e 0 /app/configure_conman
exec conmand -F -v -c /etc/conman.conf
