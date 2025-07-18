# Agent Guidelines for domain_watcher

## Build/Test Commands
- Build: `go build -o domain_watcher main.go`
- Test all: `go test ./...`
- Test single package: `go test ./internal/pkg/certwatch`
- Run tests with verbose: `go test -v ./...`
- Run with coverage: `go test -cover ./...`

## Code Style
- Language: Go 1.24.5
- Module: `domain_watcher`
- Use tab indentation (Go standard)
- Package imports: standard libs first, then third-party, then local (`domain_watcher/...`)
- Error handling: explicit error returns, log errors with context
- Naming: camelCase for variables/functions, PascalCase for exported types
- Struct tags: use JSON tags for serialization (`json:"field_name"`)
- Logging: use standard `log` package with prefix, structured messages
- Context: use `context.Context` for cancellation and timeouts
- Concurrency: use mutexes for thread safety, channels for communication
- Time: use `time.Time` for timestamps, UTC preferred
- Interfaces: keep small and focused (e.g., `CertificateHandler`)
- Comments: document exported functions and types only