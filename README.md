# Domain Watcher

A modular Go CLI application for monitoring domain certificate transparency logs using real-time streams and historical queries.

## Features

- **Real-time Monitoring**: Watch certificate transparency logs for new certificates issued to your domains
- **Subdomain Support**: Monitor subdomains automatically or explicitly
- **Modular Architecture**: Extensible design for adding new data sources and outputs
- **Multiple Output Formats**: JSON, table, and file outputs
- **Historical Queries**: Retrieve historical certificate data (placeholder for future CT log API integration)
- **Configurable Storage**: File-based and log-based storage handlers

## Installation

### Build from Source

```bash
git clone <repository-url>
cd domain_watcher
go mod tidy
go build -o domain_watcher .
```

### Dependencies

- Go 1.24+
- [github.com/CaliDog/certstream-go](https://github.com/CaliDog/certstream-go) - Certificate Transparency stream client
- [github.com/spf13/cobra](https://github.com/spf13/cobra) - CLI framework
- [github.com/spf13/viper](https://github.com/spf13/viper) - Configuration management

## Usage

### Monitor Domains

Start real-time monitoring for one or more domains:

```bash
# Monitor a single domain
./domain_watcher monitor example.com

# Monitor multiple domains with subdomains
./domain_watcher monitor example.com another.com --subdomains

# Output to files with table format
./domain_watcher monitor example.com --output-path ./certs --output table

# Save to log file
./domain_watcher monitor example.com --log-file ./certs.log
```

### List Monitored Domains

```bash
# List in table format
./domain_watcher list

# List in JSON format
./domain_watcher list --output json
```

### Query Historical Data

```bash
# Get historical certificates for a domain
./domain_watcher history example.com

# Get certificates from the last 30 days
./domain_watcher history example.com --days 30
```

### Global Options

- `--verbose`: Enable verbose logging
- `--output`: Set output format (json, table, yaml)
- `--config`: Specify configuration file path

## Configuration

Create a configuration file at `~/.domain_watcher.yaml`:

```yaml
verbose: true
output: "json"
monitor:
  subdomains: true
  output-path: "./certificates"
  log-file: "./domain_watcher.log"
history:
  days: 90
```

## Architecture

### Project Structure

```
domain_watcher/
├── cmd/                    # CLI commands
│   ├── root.go            # Root command and configuration
│   ├── monitor.go         # Real-time monitoring command
│   └── list.go            # List and history commands
├── internal/pkg/
│   ├── certwatch/         # Certificate transparency monitoring
│   │   ├── monitor.go     # Core monitoring logic
│   │   └── monitor_test.go # Tests
│   └── storage/           # Storage handlers
│       └── handlers.go    # File and log handlers
├── pkg/models/            # Data models
│   └── certificate.go    # Certificate and domain models
├── main.go               # Application entry point
└── go.mod               # Go module definition
```

### Core Components

1. **Monitor**: Core certificate transparency monitoring using certstream-go
2. **Storage Handlers**: Pluggable storage backends (file, log, database)
3. **CLI Commands**: Cobra-based command-line interface
4. **Models**: Data structures for certificates and domain configuration

### Extensibility

The system is designed to be modular:

- **New Data Sources**: Implement additional CT log sources or certificate APIs
- **Storage Backends**: Add database storage, cloud storage, or webhook handlers
- **Output Formats**: Add new output formats (XML, CSV, etc.)
- **Monitoring Sources**: Extend beyond CT logs to DNS monitoring, WHOIS, etc.

## Certificate Data Structure

```json
{
  "domain": "example.com",
  "subdomains": ["www.example.com", "api.example.com"],
  "leaf_cert": {
    "subject": {
      "common_name": "example.com",
      "organization": "Example Corp",
      "country": "US"
    },
    "extensions": {
      "subject_alt_name": ["example.com", "www.example.com"]
    },
    "not_before": "2024-01-01T00:00:00Z",
    "not_after": "2024-12-31T23:59:59Z",
    "issuer_distinguished_name": "Let's Encrypt Authority X3"
  },
  "timestamp": "2024-01-01T12:00:00Z",
  "log_url": "https://ct.googleapis.com/pilot/",
  "index": 123456789
}
```

## Development

### Running Tests

```bash
go test ./...
```

### Adding New Storage Handlers

Implement the `CertificateHandler` interface:

```go
type CertificateHandler interface {
    Handle(entry *models.CertificateEntry) error
}
```

Example:

```go
type DatabaseHandler struct {
    db *sql.DB
}

func (h *DatabaseHandler) Handle(entry *models.CertificateEntry) error {
    // Store certificate data in database
    return nil
}
```

### Adding New Commands

Create new command files in the `cmd/` directory following the existing pattern:

```go
var newCmd = &cobra.Command{
    Use:   "new",
    Short: "New command description",
    Run:   runNew,
}

func init() {
    rootCmd.AddCommand(newCmd)
}
```

## Future Enhancements

- **Historical API Integration**: Connect to crt.sh, Google CT API, or Censys for historical data
- **Database Storage**: PostgreSQL, MySQL, or SQLite backend
- **Web Dashboard**: Web interface for monitoring and visualization
- **Alerting**: Email, Slack, or webhook notifications for new certificates
- **DNS Monitoring**: Track DNS changes alongside certificate changes
- **Certificate Analysis**: Detect suspicious certificates, expired certs, etc.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Submit a pull request

## Troubleshooting

### Connection Issues

If you experience connection issues with the certificate transparency stream:

1. Check your internet connection
2. Verify firewall settings allow outbound HTTPS connections
3. Try running with `--verbose` for detailed logs

### Performance

For high-traffic domains, consider:

1. Using file output instead of console output
2. Implementing log rotation for large log files
3. Adding rate limiting or filtering capabilities

---

For questions or support, please open an issue in the project repository.