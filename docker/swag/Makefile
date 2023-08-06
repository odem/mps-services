# Makefile Setup
.PHONY: default all install build up down restart exec purge
default:all
all: build up

# Makefile config
include .env

install:
	sudo apt install nginx docker.io docker-compose
	sudo cp nginx.conf /etc/nginx/nginx.conf
	sudo cp nginx-sites-default.conf /etc/nginx/sites-available/default
	sudo sed "s/DUMMYDOMAIN/$(SWAG_DOMAIN)/g" -i /etc/nginx/sites-available/default


# Compose targets
build: .env
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
purge: down
	sudo rm -rf $(DATA_FOLDER)/*
