package cmd

import (
	"domain_watcher/internal/pkg/certwatch"
	"domain_watcher/internal/pkg/storage"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var monitorCmd = &cobra.Command{
	Use:   "monitor [domain...]",
	Short: "Monitor domains for certificate transparency events",
	Long: `Monitor one or more domains for certificate transparency events.
	
This command will start a real-time monitor that watches for new certificates
issued for the specified domains. You can specify multiple domains and configure
whether to include subdomains.

Examples:
  domain_watcher monitor example.com
  domain_watcher monitor example.com another.com --subdomains
  domain_watcher monitor example.com --output-path ./certs --output-format table`,
	Args: cobra.MinimumNArgs(1),
	Run:  runMonitor,
}

func init() {
	rootCmd.AddCommand(monitorCmd)

	monitorCmd.Flags().Bool("subdomains", true, "Monitor subdomains as well")
	monitorCmd.Flags().String("output-path", "", "Output directory for certificate data (default: stdout)")
	monitorCmd.Flags().String("log-file", "", "Log file path for certificate events")

	viper.BindPFlag("monitor.subdomains", monitorCmd.Flags().Lookup("subdomains"))
	viper.BindPFlag("monitor.output-path", monitorCmd.Flags().Lookup("output-path"))
	viper.BindPFlag("monitor.log-file", monitorCmd.Flags().Lookup("log-file"))
}

func runMonitor(cmd *cobra.Command, args []string) {
	domains := args
	includeSubdomains := viper.GetBool("monitor.subdomains")
	outputPath := viper.GetString("monitor.output-path")
	outputFormat := viper.GetString("output")
	logFile := viper.GetString("monitor.log-file")

	if viper.GetBool("verbose") {
		log.Printf("Starting monitor for domains: %s", strings.Join(domains, ", "))
		log.Printf("Include subdomains: %v", includeSubdomains)
		log.Printf("Output path: %s", outputPath)
		log.Printf("Output format: %s", outputFormat)
		if logFile != "" {
			log.Printf("Log file: %s", logFile)
		}
	}

	// Create monitor
	monitor := certwatch.NewMonitor()

	// Add domains to monitor
	for _, domain := range domains {
		monitor.AddDomain(domain, includeSubdomains)
	}

	// Create file handler
	fileHandler := storage.NewFileHandler(outputPath, outputFormat)
	monitor.AddHandler(fileHandler)

	// Create log handler if specified
	if logFile != "" {
		logHandler, err := storage.NewLogHandler(logFile)
		if err != nil {
			log.Fatalf("Failed to create log handler: %v", err)
		}
		defer logHandler.Close()
		monitor.AddHandler(logHandler)
	}

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start monitoring in a goroutine
	go func() {
		if err := monitor.Start(); err != nil {
			log.Fatalf("Monitor failed: %v", err)
		}
	}()

	fmt.Printf("🔍 Monitoring certificate transparency for domains: %s\n", strings.Join(domains, ", "))
	fmt.Println("Press Ctrl+C to stop...")

	// Wait for signal
	<-sigChan
	fmt.Println("\nShutting down monitor...")
	monitor.Stop()
}
