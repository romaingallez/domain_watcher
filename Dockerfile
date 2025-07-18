# Build stage
FROM golang:1.24.5-alpine AS builder

# Set working directory
WORKDIR /app

# Install git and ca-certificates (required for fetching modules and SSL)
RUN apk add --no-cache git ca-certificates

# Copy go mod files first (for better layer caching)
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o domain_watcher main.go

# Final stage
FROM alpine:latest

# Install ca-certificates for SSL connections to CT logs
RUN apk --no-cache add ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# Set working directory
WORKDIR /app

# Create directories for config and data
RUN mkdir -p /etc/domain_watcher /app/data && \
    chown -R appuser:appgroup /app /etc/domain_watcher

# Copy binary from builder stage
COPY --from=builder /app/domain_watcher .

# Copy example config
COPY .domain_watcher.yaml.example /etc/domain_watcher/domain_watcher.yaml

# Change to non-root user
USER appuser

# Set default environment variables
ENV DOMAIN_WATCHER_VERBOSE=false
ENV DOMAIN_WATCHER_OUTPUT=json
ENV DOMAIN_WATCHER_MONITOR_DOMAINS=""
ENV DOMAIN_WATCHER_MONITOR_SUBDOMAINS=true
ENV DOMAIN_WATCHER_MONITOR_OUTPUT_PATH=/app/data
ENV DOMAIN_WATCHER_MONITOR_LIVE=false
ENV DOMAIN_WATCHER_MONITOR_ALL_DOMAINS=false
ENV DOMAIN_WATCHER_MONITOR_POLL_INTERVAL=60s

# Expose default port (if needed for future web interface)
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ./domain_watcher list || exit 1

# Default command
ENTRYPOINT ["./domain_watcher"]
CMD ["--help"]