# Makefile Setup
.PHONY: default all install build up down restart exec purge
default:all

include .env

install:
	sudo apt install nginx docker.io docker-compose
	sudo cp nginx.conf /etc/nginx/nginx.conf
	sudo cp nginx-index.html /var/www/html/index.html
	sudo cp nginx-sites-swag.conf /etc/nginx/sites-available/swag
	sudo cp nginx-sites-mps.conf /etc/nginx/sites-available/mps
	sudo sed "s/DUMMYDOMAIN/$(SWAG_DOMAIN)/g" -i /etc/nginx/sites-available/mps
up:
	echo up
down:
	echo down
