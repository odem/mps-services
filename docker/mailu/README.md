
# Mailu config
Copy example env file and configure relevant variables.
```
cp .env-example .env
```
Start the container as daemon.
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