#!/bin/sh -e
# Copyright 2018-2020 Hewlett Packard Enterprise Development LP
stdbuf -o 0 -e 0 /app/configure_conman
exec conmand -F -v -c /etc/conman.conf
