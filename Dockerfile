# ddns-manager Docker image
# goreleaser 已完成编译，此 Dockerfile 仅负责打包
FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata

COPY ddns-manager /usr/local/bin/ddns-manager

EXPOSE 9877
VOLUME /data

ENTRYPOINT ["/usr/local/bin/ddns-manager", "-data-dir", "/data"]
