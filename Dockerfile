FROM alpine:3.24.1

RUN apk add --no-cache nftables ca-certificates setpriv \
 && update-ca-certificates

WORKDIR /app

ARG TARGETPLATFORM

COPY ${TARGETPLATFORM}/g0efilter /app/g0efilter
COPY scripts/docker/agent-entrypoint.sh /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
