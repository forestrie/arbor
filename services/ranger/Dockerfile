# Build stage
FROM golang:1.23-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum* ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.version=${VERSION:-dev} -X main.commit=${COMMIT:-unknown} -X main.buildDate=${BUILD_DATE:-unknown}" \
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
COPY --from=builder /build/ranger /app/ranger

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
