# Makefile Setup
.PHONY: default install swag mps cron-daily down
default:all

OBJS := nextcloud mailu gitlab nextcloud

install:
	sudo apt install docker.io docker-compose

swag:
	make -C swag down
	make -C nginx down
	make -C nginx swag
	make -C swag up

mps:
	make -C swag down
	make -C nginx mps
	for service in $(OBJS) ; do \
		make -C $$service up ; \
	done

down:
	make -C swag down
	make -C nginx down
	for service in $(OBJS) ; do \
		make -C $$service down ; \
	done
