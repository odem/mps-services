FROM debian
RUN apt update
RUN apt install vim net-tools openvpn uml-utilities -y
COPY entrypoint.sh /entrypoint.sh
RUN chmod a+x /entrypoint.sh
#ENTRYPOINT ["/entrypoint.sh"]
ENTRYPOINT ["tail", "-f", "/dev/null"]
