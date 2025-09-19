FROM alpine:3.22

# Install nftables and ca-certificates, clean up unnecessary binaries to harden / minimize image size
RUN apk add --no-cache nftables ca-certificates \
 && update-ca-certificates \
 && rm -rf /sbin/apk /etc/apk /lib/apk /var/cache/apk \
 && find /bin /usr/bin -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null || true \
 && find /sbin /usr/sbin -mindepth 1 -maxdepth 1 -type f ! -name nft -delete || true

WORKDIR /app

ARG TARGETPLATFORM

COPY ${TARGETPLATFORM}/g0efilter /app/g0efilter

ENTRYPOINT ["/app/g0efilter"]