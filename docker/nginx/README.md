
# nginx config
No Container! For now nginx is installed on the host
acting as a reverse-proxy for other services.
The install target copies the required config-files and replaces domain names.
The NGINX_DOMAIN environment variable controls which domains are replaced.
```
cp .env-example .env
```
Start the container as daemon.
```
make install
make swag
make mps
make down
```
