
# Mailu config
Copy example env file and configure CONTAINER_NAME, DATA_FOLDER and NEXTCLOUD_DOMAIN.
```
cp .env-example .env
```
Start the container as daemon.
```
make configure
make up
```
Other commands:
```
make down
make restart
make exec
make purge
```
