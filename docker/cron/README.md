
# cronjob config
Currently only one target is provided which fullfulls three main tasks.
First, the swag container is started to update certificates.
Second, a backup with borg is initiated.
Finally services are restarted.
The tasks are located in a seperated script.
```
make cron-daily
```
