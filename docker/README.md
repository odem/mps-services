
# mps-services control
Install prerequisites and control state of each service.
Services are hosted by using a letsencrypt certificate generated via http-auth.
In most cases, these services are running plain http and are located behind nginx
acting as a reverse-proxy and offering TLS.
As http-auth requires dedicated use of port 80/443 nginx is configured
to offer a site for 'swag' and certificate generation.
Further a reverse-proxy site 'mps' is provided,
which proxy_passes requests to local services.

In the Makefile there are four main targets to control that:
- install: Installs prerequisites and confgures nginx as reverse-proxy.
- swag: Used to create or update certificates.
- mps: Used to host all services
- down: stops all services
```
make install
make swag
make mps
make down
```
