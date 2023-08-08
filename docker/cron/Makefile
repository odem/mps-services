.PHONY: default install cron-daily status
default:all

# Makefile Setup
SHELL:=/bin/bash
NAME:=cron

install:
	sudo apt install cron

cron-daily:
	make -C .. down
	make -C .. swag
	sleep 20
	make -C .. down
	./backup-daily.bash
	make -C .. mps

status:
	@sudo crontab -l | grep -v "#"
