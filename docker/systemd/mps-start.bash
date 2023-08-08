#!/bin/bash

MPSDIR=/opt/mps-services/docker

cd "$MPSDIR" || exit 1
make autostart

