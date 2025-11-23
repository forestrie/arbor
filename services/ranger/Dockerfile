# Build stage
FROM golang:1.24-alpine AS builder

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Workspace root for ranger and its local clones
WORKDIR /build

# Copy workspace file so Go sees all local modules
COPY go.work ./

# Copy go module files for the ranger service
COPY src/go.mod src/go.sum* ./src/

# Copy local module clones explicitly so they are available to go.work and replaces
COPY go-datatrails-common ./go-datatrails-common
COPY go-datatrails-serialization ./go-datatrails-serialization
COPY go-datatrails-simplehash ./go-datatrails-simplehash
COPY go-merklelog-azure ./go-merklelog-azure
COPY go-merklelog-datatrails ./go-merklelog-datatrails
COPY go-merklelog-fs ./go-merklelog-fs
COPY go-merklelog-provider-testing ./go-merklelog-provider-testing
COPY go-merklelog ./go-merklelog

# Switch to module root for ranger
WORKDIR /build/src

# Download module dependencies (using go.work and replace directives)
RUN go mod download

# Copy application source
COPY src/ .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -ldflags="-w -s -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
  -o ranger \
  ./cmd/ranger

# Runtime stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 ranger && \
  adduser -D -u 1000 -G ranger ranger

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/src/ranger /app/ranger

# Change ownership
RUN chown -R ranger:ranger /app

# Switch to non-root user
USER ranger

# Expose port (default 9090 based on user preference)
EXPOSE 9090

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:${PORT:-9090}/healthz || exit 1

# Run the application
ENTRYPOINT ["/app/ranger"]
