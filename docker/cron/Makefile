# Makefile Setup
.PHONY: default install swag mps cron-daily down
default:all

install:
	sudo apt install cron

cron-daily:
	make -C .. down
	make -C .. swag
	sleep 20
	make -C .. down
	./backup-daily.bash
	make -C .. mps

