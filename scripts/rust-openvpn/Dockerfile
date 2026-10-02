FROM alpine:3.22

RUN apk add --no-cache curl iproute2 iptables openvpn

COPY openvpn-entrypoint.sh /usr/local/bin/emulebb-test-openvpn
RUN chmod 0555 /usr/local/bin/emulebb-test-openvpn

ENTRYPOINT ["/usr/local/bin/emulebb-test-openvpn"]
