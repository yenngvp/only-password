# Egress proxy. Agent containers sit on an internal Docker network with no
# route out; this proxy is their only way to the internet and forwards only
# to the hosts in `allowlist`.
FROM alpine:3.22
RUN apk add --no-cache tinyproxy
COPY tinyproxy.conf allowlist /etc/tinyproxy/
USER tinyproxy
EXPOSE 8888
CMD ["tinyproxy", "-d", "-c", "/etc/tinyproxy/tinyproxy.conf"]
