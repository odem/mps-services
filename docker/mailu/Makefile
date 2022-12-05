# Makefile Setup
.PHONY: default all build up down restart exec purge
default:all
all: build up

# Makefile config
include .env

# Compose targets
build:
	sudo mkdir -p $(DATA_FOLDER)
	sudo chown root:www-data $(DATA_FOLDER)
	sudo chmod g+rw $(DATA_FOLDER)
	docker-compose build
up: build
	docker-compose up -d 
down:
	docker-compose down
restart: build
	docker-compose restart
exec:
	docker exec -it $(CONTAINER_NAME) bash
account:
	docker-compose -p mailu exec admin flask mailu admin postmaster $(DOMAIN) PASSWORD
purge: down
	sudo rm -rf $(DATA_FOLDER)/*
