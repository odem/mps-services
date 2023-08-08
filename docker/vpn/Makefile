
include .env
CERT_FOLDER = $(DATA_FOLDER)/certs/$(OPENVPN_DOMAIN)
CFG_FILE = $(CERT_FOLDER)/srv/$(OPENVPN_DOMAIN)_bridged.conf
RSA_SIZE=2048
#RSA_SIZE=1024
SHELL:=/bin/bash
NAME:=vpn

default:all
.PHONY: prepare build-conf build-container up down network-down network-up \
	restart status exec testuser

all: build up

testuser:
ifneq ("$(USER)", "root")
	@echo "Please run as root! Exiting..." ; \
	exit 1
endif

prepare: .env
	sudo apt install uml-utilities
	sudo mkdir -p $(CERT_FOLDER)
	sudo mkdir -p $(DATA_FOLDER)/logs
	sudo mkdir -p $(CERT_FOLDER)/srv/status
	sudo touch $(DATA_FOLDER)/logs/$(OPENVPN_DOMAIN)_ptp.log
	sudo touch $(DATA_FOLDER)/logs/$(OPENVPN_DOMAIN)_bridged.log
	sudo touch $(CERT_FOLDER)/srv/status/openvpn_status.log
	sudo touch $(CERT_FOLDER)/srv/status/ipp.txt

$(CFG_FILE):
	sudo ./create_certs_vpn.bash -o $(DATA_FOLDER)/certs -R $(OPENVPN_HOSTIP) \
		-r $(RSA_SIZE) -a 256 -d 3650 -s $(OPENVPN_DOMAIN) -y -S -C -p -t all \
		-u odemwin,odemlinux,gatekeeper,ns1,ns2,storage,nas
	#sudo chown $(USER):$(USER) -R $(DATA_FOLDER)/certs/
	#sudo chmod a+rx $(CERT_FOLDER) && sudo chmod a+rx $(CERT_FOLDER)

build: | testuser network-down prepare $(CFG_FILE)
	docker-compose build

network-up: testuser
	@echo "Adding iptables rules for tunVpnGW"
	sudo iptables -I FORWARD -i tunVpnGW -o eth0 -m conntrack --ctstate NEW -j ACCEPT
	sudo iptables -I FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
	sudo iptables -t nat -I POSTROUTING -o eth0 -j MASQUERADE

network-down: testuser
	@echo "Remove iptables rules for tunVpnGW"
	-@sudo iptables -D FORWARD -i tunVpnGW -o eth0 -m conntrack --ctstate NEW -j ACCEPT 1>&2 2>/dev/null
	-@sudo iptables -D FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 1>&2 2>/dev/null
	-@sudo iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE 1>&2 2>/dev/null

up: | testuser build network-up
	sudo docker-compose up -d

down: | testuser network-down
	docker-compose down

restart: | testuser build
	docker-compose restart
status:
	@echo -n "$(NAME)       : "
	@echo -n "HTTP(NONE) -> "
	@NEEDED=2 ; CNT=`docker ps --format '{{.Names}}' | grep $(NAME) | wc -l` ; \
		echo "DOCKER ( $$CNT /  $$NEEDED)" ;

exec:
	docker exec -ti $(CONTAINER_NAME) bash

purge: | testuser down
	sudo rm -rf $(DATA_FOLDER)
