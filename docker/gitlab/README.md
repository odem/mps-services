
# gitlab config
Copy example env file and configure CONTAINER_NAME, DATA_FOLDER and GITLAB_DOMAIN.
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
