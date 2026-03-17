# Build stage
FROM golang:1.24-alpine AS builder

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /build

# Copy module files and download dependencies
COPY src/go.mod src/go.sum* ./
RUN go mod download

# Copy application source
COPY src/ ./

# Build the application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -ldflags="-w -s -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
  -o custodian \
  ./cmd/custodian

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

RUN addgroup -g 1000 custodian && \
  adduser -D -u 1000 -G custodian custodian

WORKDIR /app

COPY --from=builder /build/custodian /app/custodian

RUN chown -R custodian:custodian /app

USER custodian

EXPOSE 9092

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:${PORT:-9092}/healthz || exit 1

ENTRYPOINT ["/app/custodian"]
