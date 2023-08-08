
# vpn config
Copy example env file and configure CONTAINER_NAME, DATA_FOLDER,
OPENVPN_DOMAIN, OPENVPN_MODE and OPENVPN_HOSTIP.
Certificates are generated automatically by configured Makefile options.

```
cp .env-example .env
```
Start the container as daemon.
```
make build
make up
```
Other commands:
```
make down
make restart
make exec
make purge
```
