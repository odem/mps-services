FROM debian
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    echo "slapd slapd/internal/adminpw password secret" | debconf-set-selections && \
    echo "slapd slapd/internal/generated_adminpw password secret" | debconf-set-selections && \
    echo "slapd slapd/password1 password secret" | debconf-set-selections && \
    echo "slapd slapd/password2 password secret" | debconf-set-selections && \
    echo "slapd slapd/domain string justaname.de" | debconf-set-selections && \
    echo "slapd shared/organization string JustAName" | debconf-set-selections && \
    echo "slapd slapd/backend select MDB" | debconf-set-selections && \
    apt-get install -y slapd ldap-utils net-tools psmisc procps apt-utils vim openssl gnutls-bin ca-certificates && \
    rm -rf /var/lib/apt/lists/*
RUN update-ca-certificates
RUN mkdir -p /etc/ldap/ssl
COPY entrypoint.bash /entrypoint.bash
EXPOSE 389
EXPOSE 636
ENTRYPOINT ["/entrypoint.bash"]
CMD ["slapd", "-h", "ldapi:/// ldap:/// ldaps:///", "-d", "1"]
