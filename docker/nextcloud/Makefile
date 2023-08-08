# Makefile Setup
.PHONY: default all build up down restart status statusdocker statusweb \
	exec purge
default:all
all: build up

# Makefile config
include .env
SHELL:=/bin/bash
NAME:=nextcloud

# Compose targets
build: .env
	sudo mkdir -p $(DATA_FOLDER)
	sudo chown root:www-data $(DATA_FOLDER)
	sudo chmod g+rw $(DATA_FOLDER)
	docker-compose build
up: build
	docker-compose up -d
down:
	docker-compose down 1>&2 2>/dev/null
restart: build
	docker-compose restart
status:
	@echo -n "$(NAME) : "
	@CODE=`curl -I https://$(NAME).$(NEXTCLOUD_DOMAIN):443/login 2>/dev/null \
		| head -n 1 | cut -d' ' -f2` ; echo -n "HTTP($$CODE ) -> "
	@NEEDED=1 ; CNT=`docker ps --format '{{.Names}}' | grep $(NAME) | wc -l` ; \
		echo "DOCKER ( $$CNT /  $$NEEDED)" ;
exec:
	docker exec -it $(CONTAINER_NAME) bash
purge: down
	sudo rm -rf $(DATA_FOLDER)/*
