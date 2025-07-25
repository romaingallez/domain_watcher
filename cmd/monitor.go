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
	"time"

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
  --poll-interval: Set polling interval (default: 1m). Examples: 30s, 2m, 1h
  --certstream-url: Set certstream websocket URL (default: wss://certstream.calidog.io)

Examples:
  domain_watcher monitor example.com
  domain_watcher monitor example.com another.com --subdomains
  domain_watcher monitor example.com --live --output-path ./certs
  domain_watcher monitor --all-domains --live
  domain_watcher monitor example.com --poll-interval 30s
  domain_watcher monitor example.com --live --certstream-url ws://localhost:8080`,
	Args: func(cmd *cobra.Command, args []string) error {
		allDomains, _ := cmd.Flags().GetBool("all-domains")
		if allDomains {
			return nil // No domain args needed for all-domains mode
		}

		// Check if domains are provided via args, flag, or environment variable
		if len(args) > 0 {
			return nil // Domains provided as arguments
		}

		// Check if domains are provided via environment variable
		envDomains := viper.GetStringSlice("monitor.domains")
		if len(envDomains) > 0 {
			return nil // Domains provided via environment variable
		}

		return fmt.Errorf("no domains specified. Provide domains as arguments, via --domains flag, or set DOMAIN_WATCHER_MONITOR_DOMAINS environment variable")
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
	monitorCmd.Flags().Duration("poll-interval", 60*time.Second, "Polling interval for certificate checks (e.g., 30s, 2m, 1h)")
	monitorCmd.Flags().StringSlice("domains", []string{}, "Domains to monitor (can also be set via DOMAIN_WATCHER_MONITOR_DOMAINS env var)")
	monitorCmd.Flags().String("certstream-url", "wss://certstream.calidog.io", "Certstream websocket URL (can also be set via DOMAIN_WATCHER_CERTSTREAM_URL env var)")

	viper.BindPFlag("monitor.subdomains", monitorCmd.Flags().Lookup("subdomains"))
	viper.BindPFlag("monitor.output-path", monitorCmd.Flags().Lookup("output-path"))
	viper.BindPFlag("monitor.log-file", monitorCmd.Flags().Lookup("log-file"))
	viper.BindPFlag("monitor.live", monitorCmd.Flags().Lookup("live"))
	viper.BindPFlag("monitor.all-domains", monitorCmd.Flags().Lookup("all-domains"))
	viper.BindPFlag("monitor.poll-interval", monitorCmd.Flags().Lookup("poll-interval"))
	viper.BindPFlag("monitor.domains", monitorCmd.Flags().Lookup("domains"))
	viper.BindPFlag("monitor.certstream-url", monitorCmd.Flags().Lookup("certstream-url"))
}

func runMonitor(cmd *cobra.Command, args []string) {
	// Get domains from args first, then from environment variable if no args provided
	var domains []string
	if len(args) > 0 {
		domains = args
	} else {
		// Try to get domains from environment variable or flag
		envDomains := viper.GetStringSlice("monitor.domains")
		if len(envDomains) > 0 {
			// Check if we have a single string that needs to be split
			if len(envDomains) == 1 && strings.Contains(envDomains[0], ",") {
				domains = strings.Split(envDomains[0], ",")
				// Trim whitespace from each domain
				for i, domain := range domains {
					domains[i] = strings.TrimSpace(domain)
				}
			} else {
				domains = envDomains
			}
		} else {
			// Fallback: try to get as a single string and split by comma
			domainsStr := viper.GetString("monitor.domains")
			if domainsStr != "" {
				domains = strings.Split(domainsStr, ",")
				// Trim whitespace from each domain
				for i, domain := range domains {
					domains[i] = strings.TrimSpace(domain)
				}
			}
		}
	}

	includeSubdomains := viper.GetBool("monitor.subdomains")
	outputPath := viper.GetString("monitor.output-path")
	outputFormat := viper.GetString("output")
	logFile := viper.GetString("monitor.log-file")
	liveMode := viper.GetBool("monitor.live")
	allDomains := viper.GetBool("monitor.all-domains")
	pollInterval := viper.GetDuration("monitor.poll-interval")
	certstreamURL := viper.GetString("monitor.certstream-url")

	if viper.GetBool("verbose") {
		if allDomains {
			log.Printf("Starting monitor for ALL DOMAINS")
		} else {
			log.Printf("Starting monitor for domains: %s", strings.Join(domains, ", "))
		}
		log.Printf("Include subdomains: %v", includeSubdomains)
		log.Printf("Live mode: %v", liveMode)
		log.Printf("All domains mode: %v", allDomains)
		if liveMode {
			log.Printf("Certstream URL: %s", certstreamURL)
		}
		log.Printf("Output path: %s", outputPath)
		log.Printf("Output format: %s", outputFormat)
		if !liveMode {
			log.Printf("Polling interval: %v", pollInterval)
		}
		if logFile != "" {
			log.Printf("Log file: %s", logFile)
		}
	}

	// Create monitor
	monitor := certwatch.NewMonitorWithCertstreamURL(certstreamURL)

	// Configure monitor modes
	if liveMode {
		monitor.SetLiveMode(true)
	} else {
		monitor.SetPollInterval(pollInterval)
	}
	if allDomains {
		monitor.SetAllDomainsMode(true)
	}

	// Add domains to monitor (unless in all-domains mode)
	if !allDomains {
		if len(domains) == 0 {
			log.Fatal("No domains specified. Provide domains as arguments, via --domains flag, or set DOMAIN_WATCHER_MONITOR_DOMAINS environment variable")
		}
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
