# Stage 1: Build
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

# Stage 2: Runtime
FROM alpine:3.24.1

RUN apk add --no-cache nftables ca-certificates \
    && update-ca-certificates

WORKDIR /app

COPY --from=builder /build/g0efilter /app/g0efilter

ENTRYPOINT ["/app/g0efilter"]
