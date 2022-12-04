# Makefile Setup
.PHONY: default all build up down restart exec purge
default:all
all: build up

# Makefile config
include .env

# Compose targets
build:
	mkdir -p $(DATA_FOLDER)
	docker-compose build
up: build
	docker-compose up -d 
down:
	docker-compose down
restart: build
	docker-compose restart
exec:
	docker exec -it nextcloud bash
purge: down
	sudo rm -rf $(DATA_FOLDER)
