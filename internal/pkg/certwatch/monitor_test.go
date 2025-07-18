package certwatch

import (
	"domain_watcher/pkg/models"
	"testing"
	"time"
)

func TestNewMonitor(t *testing.T) {
	monitor := NewMonitor()

	if monitor == nil {
		t.Fatal("NewMonitor() returned nil")
	}

	if monitor.watchedDomains == nil {
		t.Error("watchedDomains map not initialized")
	}

	if monitor.handlers == nil {
		t.Error("handlers slice not initialized")
	}

	if monitor.ctx == nil {
		t.Error("context not initialized")
	}
}

func TestAddDomain(t *testing.T) {
	monitor := NewMonitor()

	domain := "example.com"
	includeSubdomains := true

	monitor.AddDomain(domain, includeSubdomains)

	domains := monitor.GetWatchedDomains()
	if len(domains) != 1 {
		t.Errorf("Expected 1 domain, got %d", len(domains))
	}

	watchConfig, exists := domains[domain]
	if !exists {
		t.Errorf("Domain %s not found in watched domains", domain)
	}

	if watchConfig.Domain != domain {
		t.Errorf("Expected domain %s, got %s", domain, watchConfig.Domain)
	}

	if watchConfig.IncludeSubdomains != includeSubdomains {
		t.Errorf("Expected includeSubdomains %v, got %v", includeSubdomains, watchConfig.IncludeSubdomains)
	}

	if !watchConfig.Active {
		t.Error("Expected domain to be active")
	}
}

func TestRemoveDomain(t *testing.T) {
	monitor := NewMonitor()

	domain := "example.com"
	monitor.AddDomain(domain, true)

	// Verify domain was added
	domains := monitor.GetWatchedDomains()
	if len(domains) != 1 {
		t.Errorf("Expected 1 domain after adding, got %d", len(domains))
	}

	// Remove domain
	monitor.RemoveDomain(domain)

	// Verify domain was removed
	domains = monitor.GetWatchedDomains()
	if len(domains) != 0 {
		t.Errorf("Expected 0 domains after removing, got %d", len(domains))
	}
}

func TestDomainMatches(t *testing.T) {
	monitor := NewMonitor()

	tests := []struct {
		certDomain        string
		watchedDomain     string
		includeSubdomains bool
		expected          bool
		description       string
	}{
		{"example.com", "example.com", false, true, "exact match"},
		{"sub.example.com", "example.com", true, true, "subdomain match with subdomains enabled"},
		{"sub.example.com", "example.com", false, false, "subdomain match with subdomains disabled"},
		{"*.example.com", "example.com", false, true, "wildcard match"},
		{"*.sub.example.com", "example.com", true, true, "wildcard subdomain match"},
		{"other.com", "example.com", true, false, "no match"},
		{"example.org", "example.com", true, false, "different TLD"},
	}

	for _, test := range tests {
		result := monitor.domainMatches(test.certDomain, test.watchedDomain, test.includeSubdomains)
		if result != test.expected {
			t.Errorf("%s: domainMatches(%q, %q, %v) = %v, expected %v",
				test.description, test.certDomain, test.watchedDomain, test.includeSubdomains, result, test.expected)
		}
	}
}

// Mock handler for testing
type mockHandler struct {
	entries []*models.CertificateEntry
}

func (h *mockHandler) Handle(entry *models.CertificateEntry) error {
	h.entries = append(h.entries, entry)
	return nil
}

func TestAddHandler(t *testing.T) {
	monitor := NewMonitor()
	handler := &mockHandler{}

	monitor.AddHandler(handler)

	if len(monitor.handlers) != 1 {
		t.Errorf("Expected 1 handler, got %d", len(monitor.handlers))
	}
}

func TestMonitorStop(t *testing.T) {
	monitor := NewMonitor()

	// Test that Stop() doesn't panic and properly cancels context
	monitor.Stop()

	// Check if context is cancelled
	select {
	case <-monitor.ctx.Done():
		// Context is properly cancelled
	case <-time.After(100 * time.Millisecond):
		t.Error("Context was not cancelled after Stop()")
	}
}
