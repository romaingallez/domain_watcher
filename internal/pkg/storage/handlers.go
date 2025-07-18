package storage

import (
	"domain_watcher/pkg/models"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

type FileHandler struct {
	outputPath   string
	outputFormat string
}

func NewFileHandler(outputPath, outputFormat string) *FileHandler {
	return &FileHandler{
		outputPath:   outputPath,
		outputFormat: outputFormat,
	}
}

func (h *FileHandler) Handle(entry *models.CertificateEntry) error {
	if h.outputPath == "" {
		// Default to stdout if no output path specified
		return h.writeToStdout(entry)
	}

	// Ensure output directory exists
	if err := os.MkdirAll(filepath.Dir(h.outputPath), 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Create filename with timestamp and domain
	timestamp := entry.Timestamp.Format("20060102_150405")
	filename := fmt.Sprintf("%s_%s.json", timestamp, sanitizeDomain(entry.Domain))
	fullPath := filepath.Join(h.outputPath, filename)

	return h.writeToFile(entry, fullPath)
}

func (h *FileHandler) writeToStdout(entry *models.CertificateEntry) error {
	switch h.outputFormat {
	case "json":
		data, err := json.MarshalIndent(entry, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		fmt.Println(string(data))
	case "yaml":
		// For simplicity, we'll use JSON for now. YAML library can be added later
		log.Println("YAML output format not yet implemented, using JSON")
		fallthrough
	case "table":
		h.printTable(entry)
	default:
		return fmt.Errorf("unsupported output format: %s", h.outputFormat)
	}
	return nil
}

func (h *FileHandler) writeToFile(entry *models.CertificateEntry, filename string) error {
	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", filename, err)
	}
	defer file.Close()

	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("failed to write to file %s: %w", filename, err)
	}

	log.Printf("Certificate data written to: %s", filename)
	return nil
}

func (h *FileHandler) printTable(entry *models.CertificateEntry) {
	fmt.Printf("┌─────────────────────────────────────────────────────────────┐\n")
	fmt.Printf("│ Certificate Transparency Entry                              │\n")
	fmt.Printf("├─────────────────────────────────────────────────────────────┤\n")
	fmt.Printf("│ Domain:        %-44s │\n", entry.Domain)
	fmt.Printf("│ Timestamp:     %-44s │\n", entry.Timestamp.Format(time.RFC3339))
	fmt.Printf("│ Subject CN:    %-44s │\n", entry.LeafCert.Subject.CommonName)
	fmt.Printf("│ Issuer:        %-44s │\n", entry.LeafCert.IssuerDistinguishedName)
	fmt.Printf("│ Not Before:    %-44s │\n", entry.LeafCert.NotBefore.Format(time.RFC3339))
	fmt.Printf("│ Not After:     %-44s │\n", entry.LeafCert.NotAfter.Format(time.RFC3339))
	if len(entry.Subdomains) > 0 {
		fmt.Printf("│ Subdomains:    %-44s │\n", fmt.Sprintf("(%d found)", len(entry.Subdomains)))
		for i, subdomain := range entry.Subdomains {
			if i < 3 { // Limit display to first 3 subdomains
				fmt.Printf("│   - %-51s │\n", subdomain)
			} else if i == 3 {
				fmt.Printf("│   - %-51s │\n", "... and more")
				break
			}
		}
	}
	fmt.Printf("└─────────────────────────────────────────────────────────────┘\n\n")
}

func sanitizeDomain(domain string) string {
	// Replace characters that are not safe for filenames
	safe := ""
	for _, r := range domain {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			safe += string(r)
		} else {
			safe += "_"
		}
	}
	return safe
}

// LogHandler writes certificate entries to a rotating log file
type LogHandler struct {
	logFile *os.File
}

func NewLogHandler(logPath string) (*LogHandler, error) {
	if err := os.MkdirAll(filepath.Dir(logPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	return &LogHandler{logFile: file}, nil
}

func (h *LogHandler) Handle(entry *models.CertificateEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	logLine := fmt.Sprintf("%s %s\n", time.Now().Format(time.RFC3339), string(data))
	if _, err := h.logFile.WriteString(logLine); err != nil {
		return fmt.Errorf("failed to write to log file: %w", err)
	}

	return h.logFile.Sync()
}

func (h *LogHandler) Close() error {
	if h.logFile != nil {
		return h.logFile.Close()
	}
	return nil
}
