# Makefile Setup
.PHONY: default all build up down restart status exec purge
default:all
all: build up

# Makefile config
include .env
SHELL:=/bin/bash
NAME:=portainer

# Compose targets
build: .env
	sudo mkdir -p $(DATA_FOLDER)
	sudo chown root:www-data $(DATA_FOLDER)
	sudo chmod g+rw $(DATA_FOLDER)
	docker-compose build
up: build
	sudo docker-compose up -d
down:
	docker-compose down
restart: build
	docker-compose restart
status:
	@echo -n "$(NAME) : "
	@CODE=`curl -I https://$(NAME).$(PORTAINER_DOMAIN):443 2>/dev/null \
		| head -n 1 | cut -d' ' -f2` ; echo -n "HTTP($$CODE ) -> "
	@NEEDED=1 ; CNT=`docker ps --format '{{.Names}}' | grep $(NAME) | wc -l` ; \
		echo "DOCKER ( $$CNT /  $$NEEDED)" ;
exec:
	@echo "$(CONTAINER_NAME): No shell installed! Skipping..."
purge: down
	sudo rm -rf $(DATA_FOLDER)/*
