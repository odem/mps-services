FROM nextcloud
COPY apache2.conf /etc/apache2/sites-available
RUN cd /etc/apache2/mods-enabled \
    && ln -s ../mods-available/socache_shmcb.conf \
    && ln -s ../mods-available/socache_shmcb.load \
    && ln -s ../mods-available/ssl.conf \
    && ln -s ../mods-available/ssl.load \
    && cd /etc/apache2/sites-enabled \
    && ln -s ../sites-available/apache2.conf \
	&& mkdir -p /certs
ENTRYPOINT ["/entrypoint.sh", "apache2-foreground"]
