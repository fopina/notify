FROM alpine:latest

COPY notify /usr/local/bin/notify

ENTRYPOINT ["notify"]
