# Build stage
FROM golang:1.24-alpine AS builder

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Workspace root (Docker build context is expected to be the services/ directory)
WORKDIR /build

# Copy workspace file so Go sees all local modules
COPY sealer/go.work ./sealer/go.work

# Copy go module files for the sealer service
COPY sealer/src/go.mod sealer/src/go.sum* ./sealer/src/

# Copy shared packages used via go.work
COPY pkgs/s3storage ./pkgs/s3storage
COPY pkgs/delegationcert ./pkgs/delegationcert

# Copy local module clones explicitly so they are available to go.work and replaces
COPY _deps/go-sigv4 ./_deps/go-sigv4
COPY _deps/go-datatrails-common ./_deps/go-datatrails-common
COPY _deps/go-datatrails-serialization ./_deps/go-datatrails-serialization
COPY _deps/go-datatrails-simplehash ./_deps/go-datatrails-simplehash
COPY _deps/go-merklelog-azure ./_deps/go-merklelog-azure
COPY _deps/go-merklelog-datatrails ./_deps/go-merklelog-datatrails
COPY _deps/go-merklelog-fs ./_deps/go-merklelog-fs
COPY _deps/go-merklelog-provider-testing ./_deps/go-merklelog-provider-testing
COPY _deps/go-merklelog ./_deps/go-merklelog

# Switch to module root for sealer
WORKDIR /build/sealer/src

# Download module dependencies (using go.work and replace directives)
RUN go mod download

# Copy application source
COPY sealer/src/ .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -ldflags="-w -s -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
  -o sealer \
  ./cmd/sealer

# Runtime stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 sealer && \
  adduser -D -u 1000 -G sealer sealer

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/sealer/src/sealer /app/sealer

# Change ownership
RUN chown -R sealer:sealer /app

# Switch to non-root user
USER sealer

# Expose port
EXPOSE 9090

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:${PORT:-9090}/healthz || exit 1

# Run the application
ENTRYPOINT ["/app/sealer"]
