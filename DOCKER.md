# Docker Usage Guide

## Environment Variables

The application supports environment variables with the `DOMAIN_WATCHER_` prefix:

| Environment Variable | CLI Flag | Default | Description |
|---------------------|----------|---------|-------------|
| `DOMAIN_WATCHER_VERBOSE` | `--verbose` | `false` | Enable verbose output |
| `DOMAIN_WATCHER_OUTPUT` | `--output` | `json` | Output format (json, yaml, table) |
| `DOMAIN_WATCHER_MONITOR_DOMAINS` | `--domains` | `` | Comma-separated list of domains to monitor |
| `DOMAIN_WATCHER_MONITOR_SUBDOMAINS` | `--subdomains` | `true` | Monitor subdomains |
| `DOMAIN_WATCHER_MONITOR_OUTPUT_PATH` | `--output-path` | `/app/data` | Output directory for certificates |
| `DOMAIN_WATCHER_MONITOR_LOG_FILE` | `--log-file` | `` | Log file path |
| `DOMAIN_WATCHER_MONITOR_LIVE` | `--live` | `false` | Use live streaming mode |
| `DOMAIN_WATCHER_MONITOR_ALL_DOMAINS` | `--all-domains` | `false` | Monitor all certificates |
| `DOMAIN_WATCHER_MONITOR_POLL_INTERVAL` | `--poll-interval` | `60s` | Polling interval |

## Quick Start

### Build and Run
```bash
# Build the image
docker build -t domain_watcher .

# Run with environment variables
docker run -e DOMAIN_WATCHER_VERBOSE=true \
           -e DOMAIN_WATCHER_MONITOR_LIVE=true \
           -v $(pwd)/data:/app/data \
           domain_watcher monitor example.com
```

### Using Docker Compose
```bash
# Start services
docker-compose up -d

# View logs
docker-compose logs -f domain_watcher

# Stop services
docker-compose down
```

## Domain Specification Methods

You can specify domains to monitor in three ways:

### 1. Command Line Arguments (Traditional)
```bash
docker run domain_watcher monitor example.com google.com
```

### 2. Environment Variable (Recommended for Docker)
```bash
# Single domain
docker run -e DOMAIN_WATCHER_MONITOR_DOMAINS="example.com" \
           domain_watcher monitor

# Multiple domains (comma-separated)
docker run -e DOMAIN_WATCHER_MONITOR_DOMAINS="example.com,google.com,github.com" \
           domain_watcher monitor
```

### 3. Flag
```bash
docker run domain_watcher monitor --domains example.com,google.com
```

## Advanced Usage Examples

### Monitor Single Domain via Environment Variable
```bash
docker run -e DOMAIN_WATCHER_VERBOSE=true \
           -e DOMAIN_WATCHER_MONITOR_DOMAINS="example.com" \
           -e DOMAIN_WATCHER_MONITOR_LIVE=true \
           -v $(pwd)/data:/app/data \
           domain_watcher monitor
```

### Monitor Multiple Domains
```bash
docker run -e DOMAIN_WATCHER_MONITOR_DOMAINS="example.com,google.com,github.com" \
           -e DOMAIN_WATCHER_MONITOR_SUBDOMAINS=true \
           -e DOMAIN_WATCHER_VERBOSE=true \
           domain_watcher monitor
```

### All Domains Mode (Monitor Everything)
```bash
docker run -e DOMAIN_WATCHER_MONITOR_ALL_DOMAINS=true \
           -e DOMAIN_WATCHER_MONITOR_LIVE=true \
           -e DOMAIN_WATCHER_VERBOSE=true \
           domain_watcher monitor
```

### Custom Configuration with Docker Compose
```yaml
# docker-compose.override.yml
services:
  domain_watcher:
    environment:
      DOMAIN_WATCHER_MONITOR_DOMAINS: "mycompany.com,app.mycompany.com"
      DOMAIN_WATCHER_MONITOR_LIVE: "true"
      DOMAIN_WATCHER_VERBOSE: "true"
    command: ["monitor"]
```

### Persistent Data and Logs
```bash
docker run -e DOMAIN_WATCHER_MONITOR_DOMAINS="example.com" \
           -e DOMAIN_WATCHER_MONITOR_OUTPUT_PATH="/app/data" \
           -e DOMAIN_WATCHER_MONITOR_LOG_FILE="/app/data/monitor.log" \
           -v $(pwd)/cert-data:/app/data \
           domain_watcher monitor
```