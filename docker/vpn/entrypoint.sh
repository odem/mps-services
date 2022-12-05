#!/bin/bash

cd /etc/openvpn/server/$OPENVPN_DOMAIN
mkdir tmp &>/dev/null

if [ "$OPENVPN_MODE" = "bridge" ] ; then
    openvpn --config ${OPENVPN_DOMAIN}_bridged.conf
elif [ "$OPENVPN_MODE" = "ptp" ] ; then
    openvpn --config ${OPENVPN_DOMAIN}_ptp.conf
else
    echo "No Mode specified Specify Mode with 'OPENVPN_HOME=MODE'"
fi

