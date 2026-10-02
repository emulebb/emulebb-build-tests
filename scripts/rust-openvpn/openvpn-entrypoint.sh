#!/bin/sh
set -eu

umask 077
mkdir -p /run/openvpn
{
    tr -d '\r\n' < /run/secrets/openvpn_user
    printf '\n'
    tr -d '\r\n' < /run/secrets/openvpn_password
    printf '\n'
} > /run/openvpn/auth.conf

exec openvpn \
    --cd /gluetun \
    --config custom.conf \
    --auth-user-pass /run/openvpn/auth.conf
