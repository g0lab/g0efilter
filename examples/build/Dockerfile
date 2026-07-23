# Build the agent.
FROM golang:1.26.5-alpine3.23 AS builder

ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ENV CGO_ENABLED=0 GOOS=linux
RUN go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -o /build/g0efilter ./agent

# Create the runtime image.
FROM alpine:3.24.1

RUN apk add --no-cache nftables ca-certificates setpriv \
    && update-ca-certificates

WORKDIR /app

COPY --from=builder /build/g0efilter /app/g0efilter
COPY scripts/docker/agent-entrypoint.sh /app/entrypoint.sh

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/app/g0efilter", "healthcheck"]

ENTRYPOINT ["/app/entrypoint.sh"]
