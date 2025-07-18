package certwatch

import (
	"context"
	"crypto/x509"
	"domain_watcher/pkg/models"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/jmoiron/jsonq"
	"github.com/pathtofile/certstream-go"
)

type CTLogInfo struct {
	URL         string `json:"url"`
	Description string `json:"description"`
	LogID       string `json:"log_id"`
}

type CTLogOperator struct {
	Name string      `json:"name"`
	Logs []CTLogInfo `json:"logs"`
}

type CTLogList struct {
	Operators []CTLogOperator `json:"operators"`
}

type CTLogClient struct {
	client    *client.LogClient
	url       string
	name      string
	lastIndex int64
}

type Monitor struct {
	watchedDomains map[string]*models.DomainWatch
	mutex          sync.RWMutex
	handlers       []CertificateHandler
	stopChan       chan struct{}
	ctx            context.Context
	cancel         context.CancelFunc
	ctClients      []*CTLogClient
	pollInterval   time.Duration
	httpClient     *http.Client
	liveMode       bool
	allDomainsMode bool
}

type CertificateHandler interface {
	Handle(entry *models.CertificateEntry) error
}

func NewMonitor() *Monitor {
	ctx, cancel := context.WithCancel(context.Background())

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	monitor := &Monitor{
		watchedDomains: make(map[string]*models.DomainWatch),
		handlers:       make([]CertificateHandler, 0),
		stopChan:       make(chan struct{}),
		ctx:            ctx,
		cancel:         cancel,
		ctClients:      make([]*CTLogClient, 0),
		pollInterval:   time.Minute * 1,
		httpClient:     httpClient,
	}

	// Initialize CT clients from certspotter list
	if err := monitor.initializeCTClients(); err != nil {
		log.Printf("Failed to initialize CT clients: %v", err)
	}

	return monitor
}

func (m *Monitor) initializeCTClients() error {
	// Fetch CT log list from certspotter
	resp, err := m.httpClient.Get("https://loglist.certspotter.org/monitor.json")
	if err != nil {
		return fmt.Errorf("failed to fetch CT log list: %w", err)
	}
	defer resp.Body.Close()

	var logList CTLogList
	if err := json.NewDecoder(resp.Body).Decode(&logList); err != nil {
		return fmt.Errorf("failed to decode CT log list: %w", err)
	}

	// Select active logs that are currently accepting certificates
	activeURLs := m.selectActiveLogs(logList)

	// Create clients for selected logs
	for _, url := range activeURLs {
		ctClient, err := client.New(url, m.httpClient, jsonclient.Options{})
		if err != nil {
			log.Printf("Failed to create CT client for %s: %v", url, err)
			continue
		}

		logClient := &CTLogClient{
			client:    ctClient,
			url:       url,
			name:      m.getLogName(url, logList),
			lastIndex: -1,
		}

		m.ctClients = append(m.ctClients, logClient)
		log.Printf("Initialized CT client for: %s (%s)", logClient.name, url)
	}

	if len(m.ctClients) == 0 {
		return fmt.Errorf("no CT clients could be initialized")
	}

	log.Printf("Successfully initialized %d CT clients", len(m.ctClients))
	return nil
}

func (m *Monitor) selectActiveLogs(logList CTLogList) []string {
	now := time.Now()
	activeURLs := make([]string, 0)

	// Look for logs that are currently active (temporal interval includes current time)
	for _, operator := range logList.Operators {
		for _, logInfo := range operator.Logs {
			// For simplicity, select some well-known reliable logs
			// You can modify this logic to be more sophisticated
			if m.isLogActive(logInfo, now) {
				activeURLs = append(activeURLs, logInfo.URL)

				// Limit to 5 logs to avoid overwhelming the system
				if len(activeURLs) >= 5 {
					return activeURLs
				}
			}
		}
	}

	return activeURLs
}

func (m *Monitor) isLogActive(logInfo CTLogInfo, now time.Time) bool {
	// Select logs from major operators that are likely to be reliable
	if strings.Contains(logInfo.URL, "letsencrypt.org") ||
		strings.Contains(logInfo.URL, "googleapis.com") ||
		strings.Contains(logInfo.URL, "digicert.com") ||
		strings.Contains(logInfo.URL, "cloudflare.com") ||
		strings.Contains(logInfo.URL, "sectigo.com") {

		// Prefer 2025 logs that should be active now
		if strings.Contains(logInfo.Description, "2025") {
			return true
		}
	}
	return false
}

func (m *Monitor) getLogName(url string, logList CTLogList) string {
	for _, operator := range logList.Operators {
		for _, logInfo := range operator.Logs {
			if logInfo.URL == url {
				return logInfo.Description
			}
		}
	}
	return url
}

func (m *Monitor) AddDomain(domain string, includeSubdomains bool) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.watchedDomains[domain] = &models.DomainWatch{
		Domain:            domain,
		IncludeSubdomains: includeSubdomains,
		CreatedAt:         time.Now(),
		Active:            true,
	}

	log.Printf("Added domain to watch list: %s (include subdomains: %v)", domain, includeSubdomains)
}

func (m *Monitor) RemoveDomain(domain string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.watchedDomains[domain]; exists {
		delete(m.watchedDomains, domain)
		log.Printf("Removed domain from watch list: %s", domain)
	}
}

func (m *Monitor) AddHandler(handler CertificateHandler) {
	m.handlers = append(m.handlers, handler)
}

func (m *Monitor) SetLiveMode(enabled bool) {
	m.liveMode = enabled
}

func (m *Monitor) SetAllDomainsMode(enabled bool) {
	m.allDomainsMode = enabled
}

func (m *Monitor) SetPollInterval(interval time.Duration) {
	m.pollInterval = interval
}

func (m *Monitor) Start() error {
	if m.liveMode {
		return m.startLiveMode()
	} else {
		return m.startPollingMode()
	}
}

func (m *Monitor) startPollingMode() error {
	if len(m.ctClients) == 0 {
		return fmt.Errorf("no CT clients available")
	}

	log.Printf("Starting certificate transparency monitor in POLLING mode with %d CT logs...", len(m.ctClients))
	log.Printf("Polling interval: %v", m.pollInterval)

	// Initialize starting points for each CT log
	for _, logClient := range m.ctClients {
		go m.initializeLogStartingPoint(logClient)
	}

	// Wait a bit for initialization
	time.Sleep(5 * time.Second)

	ticker := time.NewTicker(m.pollInterval)
	defer ticker.Stop()

	// Log the first poll time
	nextPoll := time.Now().Add(m.pollInterval)
	log.Printf("Next polling scheduled for: %s", nextPoll.Format("15:04:05"))

	for {
		select {
		case <-m.ctx.Done():
			log.Println("Monitor stopped")
			return nil
		case <-ticker.C:
			log.Printf("Starting polling cycle at %s", time.Now().Format("15:04:05"))

			// Check each CT log in parallel
			var wg sync.WaitGroup
			for _, logClient := range m.ctClients {
				wg.Add(1)
				go func(lc *CTLogClient) {
					defer wg.Done()
					if err := m.checkNewCertificates(lc); err != nil {
						log.Printf("Error checking %s: %v", lc.name, err)
					}
				}(logClient)
			}
			wg.Wait()

			// Log when the next poll will happen
			nextPoll := time.Now().Add(m.pollInterval)
			log.Printf("Polling cycle completed. Next poll scheduled for: %s", nextPoll.Format("15:04:05"))
		}
	}
}

func (m *Monitor) startLiveMode() error {
	log.Printf("Starting certificate transparency monitor in LIVE STREAMING mode...")

	// Create the certstream
	// stream, errChan := certstream.CertStreamEventStream(false)
	stream, errChan := certstream.CertStreamEventStreamURL(false, "ws://localhost:8080")

	for {
		select {
		case <-m.ctx.Done():
			log.Println("Live monitor stopped")
			return nil
		case jq := <-stream:
			// Process the certificate event
			m.processLiveEvent(&jq)
		case err := <-errChan:
			if err != nil {
				log.Printf("Error in live stream: %v", err)
				// Attempt to reconnect after a brief delay
				time.Sleep(5 * time.Second)
				stream, errChan = certstream.CertStreamEventStream(false)
			}
		}
	}
}

func (m *Monitor) initializeLogStartingPoint(logClient *CTLogClient) {
	sth, err := logClient.client.GetSTH(m.ctx)
	if err != nil {
		log.Printf("Failed to get initial STH for %s: %v", logClient.name, err)
		logClient.lastIndex = 0
		return
	}

	// Start 100 entries back to avoid missing recent certificates
	logClient.lastIndex = int64(sth.TreeSize) - 100
	if logClient.lastIndex < 0 {
		logClient.lastIndex = 0
	}

	log.Printf("Initialized %s starting from index: %d", logClient.name, logClient.lastIndex)
}

func (m *Monitor) Stop() {
	log.Println("Stopping certificate transparency monitor...")
	m.cancel()
	close(m.stopChan)
}

func (m *Monitor) checkNewCertificates(logClient *CTLogClient) error {
	// Get current tree head
	sth, err := logClient.client.GetSTH(m.ctx)
	if err != nil {
		return fmt.Errorf("failed to get STH: %w", err)
	}

	currentSize := int64(sth.TreeSize)
	if currentSize <= logClient.lastIndex {
		return nil // No new certificates
	}

	// Limit batch size to avoid overwhelming the API
	batchSize := int64(50) // Smaller batch for multiple logs
	endIndex := logClient.lastIndex + batchSize
	if endIndex > currentSize {
		endIndex = currentSize
	}

	// Get entries in batch
	entries, err := logClient.client.GetEntries(m.ctx, logClient.lastIndex, endIndex-1)
	if err != nil {
		return fmt.Errorf("failed to get entries: %w", err)
	}

	log.Printf("%s: Checking certificates from index %d to %d (%d entries)",
		logClient.name, logClient.lastIndex, endIndex-1, len(entries))

	for i, entry := range entries {
		index := logClient.lastIndex + int64(i)
		if err := m.processCTEntry(&entry, index, logClient); err != nil {
			log.Printf("Error processing entry %d from %s: %v", index, logClient.name, err)
		}
	}

	logClient.lastIndex = endIndex
	return nil
}

func (m *Monitor) processCTEntry(entry *ct.LogEntry, index int64, logClient *CTLogClient) error {
	var cert *x509.Certificate
	var err error

	// Parse the certificate
	switch entry.Leaf.TimestampedEntry.EntryType {
	case ct.X509LogEntryType:
		cert, err = x509.ParseCertificate(entry.Leaf.TimestampedEntry.X509Entry.Data)
	case ct.PrecertLogEntryType:
		cert, err = x509.ParseCertificate(entry.Leaf.TimestampedEntry.PrecertEntry.TBSCertificate)
	default:
		return fmt.Errorf("unknown entry type: %v", entry.Leaf.TimestampedEntry.EntryType)
	}

	if err != nil {
		// Skip malformed certificates - this is common in CT logs
		// Don't log every occurrence to avoid spam
		return nil
	}

	// Extract all domains from certificate
	allDomains := []string{}
	if cert.Subject.CommonName != "" {
		allDomains = append(allDomains, cert.Subject.CommonName)
	}
	allDomains = append(allDomains, cert.DNSNames...)

	// Check if any domain matches our watch list (or if we're in all-domains mode)
	var matchedDomain string
	var watchConfig *models.DomainWatch

	m.mutex.RLock()
	if m.allDomainsMode {
		// In all-domains mode, process every certificate
		// Use the first domain from the certificate as the "matched" domain
		if len(allDomains) > 0 {
			matchedDomain = allDomains[0]
			watchConfig = &models.DomainWatch{
				Domain:            matchedDomain,
				IncludeSubdomains: false,
				LastSeen:          time.Now(),
			}
		}
	} else {
		// Normal mode: check against watched domains
		for _, domain := range allDomains {
			for watchedDomain, config := range m.watchedDomains {
				if m.domainMatches(domain, watchedDomain, config.IncludeSubdomains) {
					matchedDomain = watchedDomain
					watchConfig = config
					break
				}
			}
			if matchedDomain != "" {
				break
			}
		}
	}
	m.mutex.RUnlock()

	if matchedDomain == "" {
		return nil // No match
	}

	// Update last seen time (only for watched domains, not all-domains mode)
	if !m.allDomainsMode {
		m.mutex.Lock()
		watchConfig.LastSeen = time.Now()
		m.mutex.Unlock()
	}

	// Create certificate entry
	certEntry := m.createCertificateEntry(cert, allDomains, matchedDomain, index, logClient)

	log.Printf("Found matching certificate for %s from %s (index %d)",
		matchedDomain, logClient.name, index)

	// Process with all handlers
	for _, handler := range m.handlers {
		if err := handler.Handle(certEntry); err != nil {
			log.Printf("Handler error: %v", err)
		}
	}

	return nil
}

func (m *Monitor) domainMatches(certDomain, watchedDomain string, includeSubdomains bool) bool {
	certDomain = strings.ToLower(strings.TrimSpace(certDomain))
	watchedDomain = strings.ToLower(strings.TrimSpace(watchedDomain))

	// Exact match
	if certDomain == watchedDomain {
		return true
	}

	// Subdomain match if enabled
	if includeSubdomains && strings.HasSuffix(certDomain, "."+watchedDomain) {
		return true
	}

	// Wildcard match
	if strings.HasPrefix(certDomain, "*.") {
		baseDomain := certDomain[2:]
		if baseDomain == watchedDomain {
			return true
		}
		if includeSubdomains && strings.HasSuffix(baseDomain, "."+watchedDomain) {
			return true
		}
	}

	return false
}

func (m *Monitor) createCertificateEntry(cert *x509.Certificate, allDomains []string, matchedDomain string, index int64, logClient *CTLogClient) *models.CertificateEntry {
	// Extract subject information
	subject := models.Subject{
		CommonName:         cert.Subject.CommonName,
		Country:            strings.Join(cert.Subject.Country, ", "),
		Organization:       strings.Join(cert.Subject.Organization, ", "),
		OrganizationalUnit: strings.Join(cert.Subject.OrganizationalUnit, ", "),
		Locality:           strings.Join(cert.Subject.Locality, ", "),
		Province:           strings.Join(cert.Subject.Province, ", "),
	}

	// Create extensions (SAN is already in allDomains)
	extensions := models.Extensions{
		SubjectAltName: cert.DNSNames,
	}

	leaf := models.LeafCertificate{
		Subject:                 subject,
		Extensions:              extensions,
		NotBefore:               cert.NotBefore,
		NotAfter:                cert.NotAfter,
		IssuerDistinguishedName: cert.Issuer.CommonName,
		Fingerprint:             fmt.Sprintf("%x", cert.Raw),
		SerialNumber:            cert.SerialNumber.String(),
	}

	// Collect all certificate domains as subdomains (since matchedDomain is the watched domain)
	var subdomains []string
	for _, domain := range allDomains {
		// Add all certificate domains to subdomains
		subdomains = append(subdomains, domain)
	}

	return &models.CertificateEntry{
		Domain:     matchedDomain,
		Subdomains: subdomains,
		LeafCert:   leaf,
		Chain:      []models.ChainCert{}, // Empty chain for live stream
		Timestamp:  time.Now(),
		LogURL:     "certstream",
		Index:      0, // Live stream doesn't provide index
	}
}

func (m *Monitor) GetWatchedDomains() map[string]*models.DomainWatch {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	result := make(map[string]*models.DomainWatch)
	for k, v := range m.watchedDomains {
		result[k] = v
	}
	return result
}

func (m *Monitor) GetHistoricalCertificates(domain string, days int) ([]*models.CertificateEntry, error) {
	log.Printf("Historical lookup for %s (last %d days) - feature not yet implemented", domain, days)
	return []*models.CertificateEntry{}, fmt.Errorf("historical lookup not yet implemented")
}

func (m *Monitor) processLiveEvent(jq *jsonq.JsonQuery) {
	messageType, err := jq.String("message_type")
	if err != nil {
		return
	}

	if messageType != "certificate_update" {
		return
	}

	// Extract certificate data
	certData, err := jq.Object("data", "leaf_cert")
	if err != nil {
		return
	}

	// Get all domain names from the certificate
	var allDomains []string

	// Get subject common name
	if subjectCN, err := jq.String("data", "leaf_cert", "subject", "CN"); err == nil && subjectCN != "" {
		allDomains = append(allDomains, subjectCN)
	}

	// Get SAN domains
	if sanArray, err := jq.Array("data", "leaf_cert", "extensions", "subjectAltName"); err == nil {
		for _, san := range sanArray {
			if sanStr, ok := san.(string); ok && sanStr != "" {
				allDomains = append(allDomains, sanStr)
			}
		}
	}

	if len(allDomains) == 0 {
		return
	}

	// Check if any domain matches our watch list (or if we're in all-domains mode)
	var matchedDomain string
	var watchConfig *models.DomainWatch

	m.mutex.RLock()
	if m.allDomainsMode {
		// In all-domains mode, process every certificate
		matchedDomain = allDomains[0]
		watchConfig = &models.DomainWatch{
			Domain:            matchedDomain,
			IncludeSubdomains: false,
			LastSeen:          time.Now(),
		}
	} else {
		// Normal mode: check against watched domains
		for _, domain := range allDomains {
			for watchedDomain, config := range m.watchedDomains {
				if m.domainMatches(domain, watchedDomain, config.IncludeSubdomains) {
					matchedDomain = watchedDomain
					watchConfig = config
					break
				}
			}
			if matchedDomain != "" {
				break
			}
		}
	}
	m.mutex.RUnlock()

	if matchedDomain == "" {
		return // No match
	}

	// Update last seen time (only for watched domains, not all-domains mode)
	if !m.allDomainsMode {
		m.mutex.Lock()
		watchConfig.LastSeen = time.Now()
		m.mutex.Unlock()
	}

	// Create certificate entry from live data
	entry := m.createLiveCertificateEntry(certData, allDomains, matchedDomain)
	if entry == nil {
		return
	}

	// Process through handlers
	for _, handler := range m.handlers {
		if err := handler.Handle(entry); err != nil {
			log.Printf("Handler error: %v", err)
		}
	}
}

func (m *Monitor) createLiveCertificateEntry(certData map[string]interface{}, allDomains []string, matchedDomain string) *models.CertificateEntry {
	// Extract certificate information from live stream data
	subject := models.Subject{}
	extensions := models.Extensions{}

	// Parse subject information
	if subjectMap, ok := certData["subject"].(map[string]interface{}); ok {
		if cn, ok := subjectMap["CN"].(string); ok {
			subject.CommonName = cn
		}
		if c, ok := subjectMap["C"].(string); ok {
			subject.Country = c
		}
		if st, ok := subjectMap["ST"].(string); ok {
			subject.Province = st
		}
		if l, ok := subjectMap["L"].(string); ok {
			subject.Locality = l
		}
		if o, ok := subjectMap["O"].(string); ok {
			subject.Organization = o
		}
		if ou, ok := subjectMap["OU"].(string); ok {
			subject.OrganizationalUnit = ou
		}
	}

	// Parse SAN extensions
	if extMap, ok := certData["extensions"].(map[string]interface{}); ok {
		if sanArray, ok := extMap["subjectAltName"].([]interface{}); ok {
			var sanDomains []string
			for _, san := range sanArray {
				if sanStr, ok := san.(string); ok {
					sanDomains = append(sanDomains, sanStr)
				}
			}
			extensions.SubjectAltName = sanDomains
		}
	}

	// Parse dates
	var notBefore, notAfter time.Time
	if nbStr, ok := certData["not_before"].(string); ok {
		if parsed, err := time.Parse(time.RFC3339, nbStr); err == nil {
			notBefore = parsed
		}
	}
	if naStr, ok := certData["not_after"].(string); ok {
		if parsed, err := time.Parse(time.RFC3339, naStr); err == nil {
			notAfter = parsed
		}
	}

	leaf := models.LeafCertificate{
		Subject:                 subject,
		Extensions:              extensions,
		NotBefore:               notBefore,
		NotAfter:                notAfter,
		IssuerDistinguishedName: getString(certData, "issuer", "CN"),
		Fingerprint:             getString(certData, "fingerprint"),
		SerialNumber:            getString(certData, "serial_number"),
	}

	// Collect all certificate domains as subdomains (since matchedDomain is the watched domain)
	var subdomains []string
	for _, domain := range allDomains {
		// Add all certificate domains to subdomains
		subdomains = append(subdomains, domain)
	}

	return &models.CertificateEntry{
		Domain:     matchedDomain,
		Subdomains: subdomains,
		LeafCert:   leaf,
		Chain:      []models.ChainCert{}, // Empty chain for live stream
		Timestamp:  time.Now(),
		LogURL:     "certstream",
		Index:      0, // Live stream doesn't provide index
	}
}

func getString(data map[string]interface{}, keys ...string) string {
	current := data
	for i, key := range keys {
		if i == len(keys)-1 {
			if val, ok := current[key].(string); ok {
				return val
			}
			return ""
		}
		if next, ok := current[key].(map[string]interface{}); ok {
			current = next
		} else {
			return ""
		}
	}
	return ""
}
