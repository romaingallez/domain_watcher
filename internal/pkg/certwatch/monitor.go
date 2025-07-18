package certwatch

import (
	"context"
	"domain_watcher/pkg/models"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/CaliDog/certstream-go"
	"github.com/jmoiron/jsonq"
)

type Monitor struct {
	watchedDomains map[string]*models.DomainWatch
	mutex          sync.RWMutex
	handlers       []CertificateHandler
	stopChan       chan struct{}
	ctx            context.Context
	cancel         context.CancelFunc
}

type CertificateHandler interface {
	Handle(entry *models.CertificateEntry) error
}

func NewMonitor() *Monitor {
	ctx, cancel := context.WithCancel(context.Background())
	return &Monitor{
		watchedDomains: make(map[string]*models.DomainWatch),
		handlers:       make([]CertificateHandler, 0),
		stopChan:       make(chan struct{}),
		ctx:            ctx,
		cancel:         cancel,
	}
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

func (m *Monitor) Start() error {
	log.Println("Starting certificate transparency monitor...")

	stream, errChan := certstream.CertStreamEventStream(false)

	for {
		select {
		case <-m.ctx.Done():
			log.Println("Monitor stopped")
			return nil
		case err := <-errChan:
			log.Printf("Error in certstream: %v", err)
			continue
		case jq := <-stream:
			m.processCertStreamEvent(&jq)
		}
	}
}

func (m *Monitor) Stop() {
	log.Println("Stopping certificate transparency monitor...")
	m.cancel()
	close(m.stopChan)
}

func (m *Monitor) processCertStreamEvent(jq *jsonq.JsonQuery) {
	messageType, err := jq.String("message_type")
	if err != nil {
		return
	}

	if messageType != "certificate_update" {
		return
	}

	data, err := jq.Object("data")
	if err != nil {
		return
	}

	dataJq := jsonq.NewQuery(data)
	leafCert, err := dataJq.Object("leaf_cert")
	if err != nil {
		return
	}

	leafJq := jsonq.NewQuery(leafCert)
	allDomains := make([]string, 0)

	// Get all domains from certificate
	if domains, err := leafJq.ArrayOfStrings("all_domains"); err == nil {
		allDomains = domains
	}

	// Check if any domain matches our watch list
	var matchedDomain string
	var watchConfig *models.DomainWatch

	m.mutex.RLock()
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
	m.mutex.RUnlock()

	if matchedDomain == "" {
		return
	}

	// Update last seen time
	m.mutex.Lock()
	watchConfig.LastSeen = time.Now()
	m.mutex.Unlock()

	// Create certificate entry
	entry := m.createCertificateEntry(dataJq, allDomains, matchedDomain)

	// Process with all handlers
	for _, handler := range m.handlers {
		if err := handler.Handle(entry); err != nil {
			log.Printf("Handler error: %v", err)
		}
	}
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

func (m *Monitor) createCertificateEntry(data *jsonq.JsonQuery, allDomains []string, matchedDomain string) *models.CertificateEntry {
	leafCert, _ := data.Object("leaf_cert")
	leafJq := jsonq.NewQuery(leafCert)

	// Extract basic certificate info
	subject := models.Subject{}
	if cn, err := leafJq.String("subject", "CN"); err == nil {
		subject.CommonName = cn
	}
	if c, err := leafJq.String("subject", "C"); err == nil {
		subject.Country = c
	}
	if o, err := leafJq.String("subject", "O"); err == nil {
		subject.Organization = o
	}
	if ou, err := leafJq.String("subject", "OU"); err == nil {
		subject.OrganizationalUnit = ou
	}
	if l, err := leafJq.String("subject", "L"); err == nil {
		subject.Locality = l
	}
	if st, err := leafJq.String("subject", "ST"); err == nil {
		subject.Province = st
	}

	// Parse dates
	var notBefore, notAfter time.Time
	if nb, err := leafJq.Float("not_before"); err == nil {
		notBefore = time.Unix(int64(nb), 0)
	}
	if na, err := leafJq.Float("not_after"); err == nil {
		notAfter = time.Unix(int64(na), 0)
	}

	// Extract extensions
	extensions := models.Extensions{}
	if sans, err := leafJq.ArrayOfStrings("extensions", "subjectAltName"); err == nil {
		extensions.SubjectAltName = sans
	}

	leaf := models.LeafCertificate{
		Subject:                 subject,
		Extensions:              extensions,
		NotBefore:               notBefore,
		NotAfter:                notAfter,
		IssuerDistinguishedName: "",
	}

	// Set issuer if available
	if issuer, err := leafJq.String("issuer", "CN"); err == nil {
		leaf.IssuerDistinguishedName = issuer
	}

	// Get fingerprint and serial
	if fp, err := leafJq.String("fingerprint"); err == nil {
		leaf.Fingerprint = fp
	}
	if sn, err := leafJq.String("serial_number"); err == nil {
		leaf.SerialNumber = sn
	}

	// Separate main domain from subdomains
	var mainDomain string
	var subdomains []string

	// Use the matched domain as main domain
	mainDomain = matchedDomain

	// Find subdomains
	for _, domain := range allDomains {
		if domain != mainDomain && strings.Contains(domain, mainDomain) {
			subdomains = append(subdomains, domain)
		}
	}

	// Get log information
	var logURL string
	var index uint64
	if url, err := data.String("log_url"); err == nil {
		logURL = url
	}
	if idx, err := data.Float("leaf_index"); err == nil {
		index = uint64(idx)
	}

	return &models.CertificateEntry{
		Domain:     mainDomain,
		Subdomains: subdomains,
		LeafCert:   leaf,
		Chain:      []models.ChainCert{}, // TODO: Parse chain certificates
		Timestamp:  time.Now(),
		LogURL:     logURL,
		Index:      index,
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

// Historical certificate lookup (placeholder for future implementation)
func (m *Monitor) GetHistoricalCertificates(domain string, days int) ([]*models.CertificateEntry, error) {
	// This would integrate with CT log APIs like crt.sh or Google's CT API
	// For now, return empty slice
	log.Printf("Historical lookup for %s (last %d days) - feature not yet implemented", domain, days)
	return []*models.CertificateEntry{}, fmt.Errorf("historical lookup not yet implemented")
}
