# Makefile Setup
.PHONY: default keys all build up down restart status statusdocker statusweb \
	exec purge
default:all
all: build up

# Makefile config
include .env
SHELL:=/bin/bash
NAME:=ldap

# Compose targets
prepare: .env
	@sudo mkdir -p $(DATA_FOLDER)
	@sudo chown root:www-data $(DATA_FOLDER)
	@sudo chmod g+rw $(DATA_FOLDER)
keys:
	if [ ! -d keys/ ]; then \
		mkdir keys ; \
	fi
	if [ ! -f keys/ldap.crt ]; then \
		echo "Generating self-signed certificate..." ; \
		openssl req -new -x509 -nodes -newkey rsa:2048 -out keys/ldap.crt \
			-keyout keys/ldap.key \
			-days 365 \
			-subj "/CN=ldap" ; \
		chmod 600 keys/ldap.key ; \
	fi

rebuild: | prepare keys
	@docker-compose build --no-cache
build: | prepare keys
	@docker-compose build
up: build
	@docker-compose up -d
down:
	@docker-compose down 2>/dev/null >/dev/null
kill:
	@docker-compose kill 2>/dev/null >/dev/null
restart: build
	@docker-compose restart
status:
	@echo -n "$(NAME) : "
	# @CODE=`curl -I https://$(NAME).$(NEXTCLOUD_DOMAIN):443/login 2>/dev/null \
	# 	| head -n 1 | cut -d' ' -f2` ; echo -n "HTTP($$CODE ) -> "
	# @NEEDED=1 ; CNT=`docker ps --format '{{.Names}}' | grep $(NAME) | wc -l` ; \
	# 	echo "DOCKER ( $$CNT /  $$NEEDED)" ;
exec:
	docker exec -it $(CONTAINER_NAME) bash
purge: kill
	sudo rm -rf $(DATA_FOLDER)/*
