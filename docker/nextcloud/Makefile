# Makefile Setup
.PHONY: default all build up down restart
default:all
all: build up

# Makefile config
include .env

# Compose targets
build:
	mkdir -p $(DATA_FOLDER)
	docker-compose build
up: build
	docker-compose up 
down:
	docker-compose down
restart: build
	docker-compose restart
