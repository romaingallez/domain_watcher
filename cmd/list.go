package cmd

import (
	"domain_watcher/internal/pkg/certwatch"
	"domain_watcher/pkg/models"
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List currently monitored domains",
	Long: `List all domains that are currently being monitored for certificate transparency events.

This command shows the domains, whether subdomains are included, when monitoring started,
and when certificates were last seen for each domain.`,
	Run: runList,
}

var historyCmd = &cobra.Command{
	Use:   "history [domain]",
	Short: "Get historical certificate data for a domain",
	Long: `Retrieve historical certificate transparency data for a specified domain.

This command queries certificate transparency logs to find historical certificates
for the given domain. Note: This feature connects to external CT log APIs.

Examples:
  domain_watcher history example.com
  domain_watcher history example.com --days 30`,
	Args: cobra.ExactArgs(1),
	Run:  runHistory,
}

func init() {
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(historyCmd)

	historyCmd.Flags().Int("days", 90, "Number of days to look back for historical data")
	viper.BindPFlag("history.days", historyCmd.Flags().Lookup("days"))
}

func runList(cmd *cobra.Command, args []string) {
	// For now, we'll create a temporary monitor to demonstrate the structure
	// In a real application, this would read from a persistent store
	monitor := certwatch.NewMonitor()

	// Add some example domains for demonstration
	// In practice, this would read from configuration or a database
	domains := monitor.GetWatchedDomains()

	if len(domains) == 0 {
		fmt.Println("No domains are currently being monitored.")
		fmt.Println("Use 'domain_watcher monitor <domain>' to start monitoring domains.")
		return
	}

	outputFormat := viper.GetString("output")

	switch outputFormat {
	case "json":
		data, err := json.MarshalIndent(domains, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(data))
	case "table":
		fallthrough
	default:
		printDomainsTable(domains)
	}
}

func printDomainsTable(domains map[string]*models.DomainWatch) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "DOMAIN\tSUBDOMAINS\tCREATED\tLAST SEEN\tSTATUS")
	fmt.Fprintln(w, "------\t----------\t-------\t---------\t------")

	for domain, config := range domains {
		subdomains := "No"
		if config.IncludeSubdomains {
			subdomains = "Yes"
		}

		status := "Inactive"
		if config.Active {
			status = "Active"
		}

		lastSeen := "Never"
		if !config.LastSeen.IsZero() {
			lastSeen = config.LastSeen.Format("2006-01-02 15:04")
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			domain,
			subdomains,
			config.CreatedAt.Format("2006-01-02 15:04"),
			lastSeen,
			status,
		)
	}

	w.Flush()
}

func runHistory(cmd *cobra.Command, args []string) {
	domain := args[0]
	days := viper.GetInt("history.days")

	if viper.GetBool("verbose") {
		fmt.Printf("Querying historical certificate data for %s (last %d days)\n", domain, days)
	}

	// Create monitor and query historical data
	monitor := certwatch.NewMonitor()
	certificates, err := monitor.GetHistoricalCertificates(domain, days)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error retrieving historical data: %v\n", err)
		os.Exit(1)
	}

	if len(certificates) == 0 {
		fmt.Printf("No certificate data found for %s in the last %d days.\n", domain, days)
		fmt.Println("Note: Historical lookup is not yet fully implemented.")
		return
	}

	outputFormat := viper.GetString("output")

	switch outputFormat {
	case "json":
		data, err := json.MarshalIndent(certificates, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(data))
	case "table":
		fallthrough
	default:
		printCertificatesTable(certificates)
	}
}

func printCertificatesTable(certificates []*models.CertificateEntry) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "DOMAIN\tSUBJECT CN\tISSUER\tNOT BEFORE\tNOT AFTER\tSUBDOMAINS")
	fmt.Fprintln(w, "------\t----------\t------\t----------\t---------\t----------")

	for _, cert := range certificates {
		subdomainCount := fmt.Sprintf("%d", len(cert.Subdomains))

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			cert.Domain,
			cert.LeafCert.Subject.CommonName,
			cert.LeafCert.IssuerDistinguishedName,
			cert.LeafCert.NotBefore.Format("2006-01-02"),
			cert.LeafCert.NotAfter.Format("2006-01-02"),
			subdomainCount,
		)
	}

	w.Flush()
}
