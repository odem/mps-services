
include .env
CERT_FOLDER = $(DATA_FOLDER)/certs/$(OPENVPN_DOMAIN)
CFG_FILE = $(CERT_FOLDER)/srv/$(OPENVPN_DOMAIN)_bridged.conf
RSA_SIZE=2048
#RSA_SIZE=1024

default:all
.PHONY: prepare build-conf build-container up down restart exec

all: build up

prepare:
	mkdir -p $(DATA_FOLDER)
	mkdir -p $(DATA_FOLDER)/logs
	mkdir -p $(CERT_FOLDER)/srv/status
	touch $(DATA_FOLDER)/logs/$(OPENVPN_DOMAIN)_ptp.log
	touch $(DATA_FOLDER)/logs/$(OPENVPN_DOMAIN)_bridged.log
	touch $(CERT_FOLDER)/srv/status/ipp.txt
	touch $(CERT_FOLDER)/srv/status/openvpn_status.log
	sudo apt install uml-utilities openvpn
	
$(CFG_FILE): 
	./create_certs_vpn.bash -o docker-data/certs -R 194.163.136.152 \
		-r $(RSA_SIZE) -a 256 -d 3650 -s $(OPENVPN_DOMAIN) -y -S -C -p -t all \
		-u odemwin,odemlinux,gatekeeper,ns1,ns2,storage,nas
	#sudo chown $(USER):$(USER) -R $(DATA_FOLDER)/certs/
	#sudo chmod a+rx $(CERT_FOLDER) && sudo chmod a+rx $(CERT_FOLDER)

build: prepare $(CFG_FILE)
	docker-compose build

up: build
	sudo docker-compose up -d

down:
	docker-compose down

restart: build
	docker-compose restart

exec:
	docker exec -ti $(CONTAINER_NAME) bash

purge: down
	sudo rm -rf $(DATA_FOLDER)
