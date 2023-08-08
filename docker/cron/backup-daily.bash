#!/bin/bash
#
BACKUP_DIR=/home/odem/borg

cd "$BACKUP_DIR" || exit 1
# SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
# cd "$SCRIPT_DIR" || exit 1

TAG=$(date '+%Y%m%d-%H%M%S')
#rm -rf backup
[[ ! -d backup ]] && mkdir backup && borg init --encryption=none backup

sudo borg create --progress --stats \
    backup::"${TAG}"-services /home/odem/mps/repo/github/odem/mps-services

sudo borg create --progress --stats \
    backup::"${TAG}"-srv /srv/docker
