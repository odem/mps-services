.PHONY: default all install build up down restart status exec purge
default:all

# Makefile Setup
include .env
SHELL:=/bin/bash
NAME:=nginx

install:
	sudo apt install nginx docker.io docker-compose
	sudo cp nginx.conf /etc/nginx/nginx.conf
	sudo cp nginx-index.html /var/www/html/index.html
	sudo cp nginx-sites-swag.conf /etc/nginx/sites-available/swag
	sudo cp nginx-sites-mps.conf /etc/nginx/sites-available/mps
	sudo sed "s/DUMMYDOMAIN/$(NGINX_DOMAIN)/g" -i /etc/nginx/sites-available/mps

swag: down
	sudo ln -s /etc/nginx/sites-available/swag /etc/nginx/sites-enabled
	sudo systemctl start nginx.service
mps: down
	sudo ln -s /etc/nginx/sites-available/mps /etc/nginx/sites-enabled
	sudo systemctl start nginx.service
status:
	@echo -n "$(NAME)     : "
	@CODE=`curl -I www.$(NGINX_DOMAIN) 2>/dev/null | head -n 1 | cut -d' ' -f2` ; \
		echo -n "HTTP($$CODE ) -> "
	@MODE=`ls /etc/nginx/sites-enabled/ | grep 'swag\|mps'` ; \
		echo "MODE  $$MODE" ;

down:
	sudo rm -rf /etc/nginx/sites-enabled/swag
	sudo rm -rf /etc/nginx/sites-enabled/mps
	sudo systemctl stop nginx.service
