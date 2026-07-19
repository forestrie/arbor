# Build stage
FROM golang:1.24-alpine AS builder

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

RUN apk add --no-cache git ca-certificates tzdata

# Workspace root (Docker build context is expected to be the services/ directory,
# so the go.mod replace ../../pkgs/logredact resolves — plan-2607-08/FOR-409)
WORKDIR /build

# Copy shared packages used via replace directives
COPY pkgs/logredact ./pkgs/logredact

# Copy module files and download dependencies
COPY scout/src/go.mod scout/src/go.sum* ./scout/src/
WORKDIR /build/scout/src
RUN go mod download

# Copy application source
COPY scout/src/ ./

# Build the application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -ldflags="-w -s -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
  -o scout \
  ./cmd/scout

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

RUN addgroup -g 1000 scout && \
  adduser -D -u 1000 -G scout scout

WORKDIR /app

COPY --from=builder /build/scout/src/scout /app/scout

RUN chown -R scout:scout /app

USER scout

EXPOSE 9090

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:${PORT:-9090}/healthz || exit 1

ENTRYPOINT ["/app/scout"]
