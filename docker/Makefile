# Makefile Setup
.PHONY: default install autostart swag mps status cron-daily down
default:status

OBJS := nextcloud mailu gitlab portainer vpn

install:
	sudo apt install docker.io docker-compose

autostart: swagrenew mps

swagrenew: swag
	sleep 10
	make -C swag down

swag:
	make -C swag down
	make -C nginx down
	make -C nginx swag
	make -C swag up

mps:
	make -C swag down
	make -C nginx mps
	for service in $(OBJS) ; do \
		make --no-print-directory -C $$service up ; \
	done

status:
	@echo ""
	@echo "Reverse-Proxy: "
	@make --no-print-directory -C nginx status
	@echo ""
	@echo "Systemd: "
	@make --no-print-directory -C systemd status
	@echo ""
	@echo "Services: "
	@for service in $(OBJS) ; do \
		make --no-print-directory -C $$service status ; \
	done
	@echo ""
	@echo "Ports: "
	@PORTS=`sudo netstat -tln | grep -v "Server)" | grep -v "Proto" \
		| awk '{print $$4}' | rev | cut -d: -f1 | rev | sort -nu \
		| tr '\n' ',' | sed 's/,$$//'` ; echo "TCP: [ $$PORTS ]"
	@PORTS=`sudo netstat -uln | grep -v "Server)" | grep -v "Proto" \
		| awk '{print $$4}' | rev | cut -d: -f1 | rev | sort -nu \
		| tr '\n' ',' | sed 's/,$$//'` ; echo "UDP: [ $$PORTS ]"
	@echo ""
	@echo "Connections: "
	@ss -tonp | grep -v "Local" | awk '{ print $$4 "<->" $$5 " " $$6 }'
	@echo ""
	@echo "Cronjobs: "
	@make --no-print-directory -C cron status
	@echo ""

down:
	make -C swag down
	make -C nginx down
	for service in $(OBJS) ; do \
		make --no-print-directory -C $$service down ; \
	done
