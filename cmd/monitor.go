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
	
This command will start a monitor that watches for new certificates
issued for the specified domains. You can specify multiple domains and configure
whether to include subdomains.

Monitoring Modes:
  --live: Use live streaming (websockets) for real-time monitoring
  --all-domains: Monitor ALL certificates (not just specified domains)

Examples:
  domain_watcher monitor example.com
  domain_watcher monitor example.com another.com --subdomains
  domain_watcher monitor example.com --live --output-path ./certs
  domain_watcher monitor --all-domains --live`,
	Args: func(cmd *cobra.Command, args []string) error {
		allDomains, _ := cmd.Flags().GetBool("all-domains")
		if allDomains {
			return nil // No domain args needed for all-domains mode
		}
		return cobra.MinimumNArgs(1)(cmd, args)
	},
	Run: runMonitor,
}

func init() {
	rootCmd.AddCommand(monitorCmd)

	monitorCmd.Flags().Bool("subdomains", true, "Monitor subdomains as well")
	monitorCmd.Flags().String("output-path", "", "Output directory for certificate data (default: stdout)")
	monitorCmd.Flags().String("log-file", "", "Log file path for certificate events")
	monitorCmd.Flags().Bool("live", false, "Use live streaming mode for real-time monitoring")
	monitorCmd.Flags().Bool("all-domains", false, "Monitor ALL certificates (not just specified domains)")

	viper.BindPFlag("monitor.subdomains", monitorCmd.Flags().Lookup("subdomains"))
	viper.BindPFlag("monitor.output-path", monitorCmd.Flags().Lookup("output-path"))
	viper.BindPFlag("monitor.log-file", monitorCmd.Flags().Lookup("log-file"))
	viper.BindPFlag("monitor.live", monitorCmd.Flags().Lookup("live"))
	viper.BindPFlag("monitor.all-domains", monitorCmd.Flags().Lookup("all-domains"))
}

func runMonitor(cmd *cobra.Command, args []string) {
	domains := args
	includeSubdomains := viper.GetBool("monitor.subdomains")
	outputPath := viper.GetString("monitor.output-path")
	outputFormat := viper.GetString("output")
	logFile := viper.GetString("monitor.log-file")
	liveMode := viper.GetBool("monitor.live")
	allDomains := viper.GetBool("monitor.all-domains")

	if viper.GetBool("verbose") {
		if allDomains {
			log.Printf("Starting monitor for ALL DOMAINS")
		} else {
			log.Printf("Starting monitor for domains: %s", strings.Join(domains, ", "))
		}
		log.Printf("Include subdomains: %v", includeSubdomains)
		log.Printf("Live mode: %v", liveMode)
		log.Printf("All domains mode: %v", allDomains)
		log.Printf("Output path: %s", outputPath)
		log.Printf("Output format: %s", outputFormat)
		if logFile != "" {
			log.Printf("Log file: %s", logFile)
		}
	}

	// Create monitor
	monitor := certwatch.NewMonitor()

	// Configure monitor modes
	if liveMode {
		monitor.SetLiveMode(true)
	}
	if allDomains {
		monitor.SetAllDomainsMode(true)
	}

	// Add domains to monitor (unless in all-domains mode)
	if !allDomains {
		for _, domain := range domains {
			monitor.AddDomain(domain, includeSubdomains)
		}
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

	if allDomains {
		fmt.Printf("🔍 Monitoring certificate transparency for ALL DOMAINS")
	} else {
		fmt.Printf("🔍 Monitoring certificate transparency for domains: %s", strings.Join(domains, ", "))
	}

	if liveMode {
		fmt.Printf(" (LIVE mode)")
	} else {
		fmt.Printf(" (polling mode)")
	}
	fmt.Println()
	fmt.Println("Press Ctrl+C to stop...")

	// Wait for signal
	<-sigChan
	fmt.Println("\nShutting down monitor...")
	monitor.Stop()
}
