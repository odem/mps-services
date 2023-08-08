# Makefile Setup
.PHONY: default all build up down restart configure exec purge
default:all
all: build up

# Makefile config
include .env

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
configure:
	docker-compose up -d
	sleep 10
	docker-compose \
		-p mailu exec admin flask mailu admin postmaster \
		$(DOMAIN) $(DEFAULT_PASSWORD)
exec:
	docker exec -it $(CONTAINER_NAME) bash
purge: down
	sudo rm -rf $(DATA_FOLDER)/*
