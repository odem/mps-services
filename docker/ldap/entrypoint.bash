#!/bin/bash

# DEBUG:
# ldapsearch -Y EXTERNAL -H ldapi:/// -LLL -b cn=config olcTLSCipherSuite
# ldapsearch -LLL -x -H ldaps://ldap:636/ -D "cn=admin,dc=justaname,dc=de" -w secret -b "ou=users,dc=justaname,dc=de"

LOGFILE=/var/log/slapd
URL_LDAPI="ldapi:///"
URL_LDAPS="ldaps://127.0.0.1:636"
DN_ADMIN="cn=admin,dc=justaname,dc=de"
DEFAULT_PW="secret"
echo "Applying TLS configuration..."
slapd -d 1 -h "$URL_LDAPI" 2>"$LOGFILE" >"$LOGFILE" &
sleep 1
ldapadd -Y EXTERNAL -H "$URL_LDAPI" -f /tmp/ldif/tls.ldif
ldapadd -Y EXTERNAL -H "$URL_LDAPI" -f /tmp/ldif/tls-ciphers.ldif
ldapadd -Y EXTERNAL -H "$URL_LDAPI" -f /tmp/ldif/tls-no-verify.ldif
slapd -d 1 -h "ldaps:///" 2>"$LOGFILE" >"$LOGFILE" &
sleep 1
echo "Dropping default users and groups..."
export LDAPTLS_REQCERT=never
ldapadd  -x -H "$URL_LDAPS" -D "$DN_ADMIN" -w "$DEFAULT_PW" -f /tmp/ldif/ou.ldif
ldapadd  -x -H "$URL_LDAPS" -D "$DN_ADMIN" -w "$DEFAULT_PW" -f /tmp/ldif/users.ldif
export LDAPTLS_REQCERT=always
killall slapd
exec "$@"  2>"$LOGFILE" >"$LOGFILE"


