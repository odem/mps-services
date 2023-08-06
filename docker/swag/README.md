
# Swag config
Copy example env file and configure CONTAINER_NAME, DATA_FOLDER, SWAG_DOMAIN
and SWAG_SUBDOMAINS.
```
cp .env-example .env

```
Start the container as daemon. Certificates will automatically renew in
'/etc/swag/etc/letsencrypt/live/YOURDOMAIN/fullchain.pem' and
'/etc/swag/etc/letsencrypt/live/YOURDOMAIN/privkey.pem'.
```
make install
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
