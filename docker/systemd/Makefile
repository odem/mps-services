# Makefile Setup
.PHONY: default install up down status
default:all

install:
	sudo cp mps.service /etc/systemd/system/mps.service
	sudo systemctl daemon-reload
	sudo systemctl enable mps.service
up:
	sudo systemctl start --no-ask-password mps.service
down:
	sudo systemctl stop --no-ask-password mps.service
status:
	@STATE=`systemctl show mps.service --property=ActiveState --no-pager \
		| grep -oP '(?<=ActiveState=)\w+'` ; \
		echo "Unit: mps.service ($$STATE)"
