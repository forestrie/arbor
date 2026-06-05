# Build stage
FROM golang:1.24-alpine AS builder

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

RUN apk add --no-cache git ca-certificates tzdata

# Workspace root (Docker build context is expected to be the services/ directory)
WORKDIR /build

COPY univocity/src/go.mod univocity/src/go.sum* ./univocity/src/

COPY pkgs/s3storage ./pkgs/s3storage

COPY _deps/go-sigv4 ./_deps/go-sigv4
COPY _deps/go-merklelog/bloom ./_deps/go-merklelog/bloom
COPY _deps/go-merklelog/massifs ./_deps/go-merklelog/massifs
COPY _deps/go-merklelog/mmr ./_deps/go-merklelog/mmr
COPY _deps/go-merklelog/urkle ./_deps/go-merklelog/urkle

WORKDIR /build/univocity/src

RUN go mod download

COPY univocity/src/ .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -ldflags="-w -s -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
  -o univocity \
  ./cmd/univocity

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata wget

RUN addgroup -g 1000 univocity && \
  adduser -D -u 1000 -G univocity univocity

WORKDIR /app

COPY --from=builder /build/univocity/src/univocity /app/univocity

RUN chown -R univocity:univocity /app

USER univocity

EXPOSE 9091

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:${PORT:-9091}/healthz || exit 1

ENTRYPOINT ["/app/univocity"]
