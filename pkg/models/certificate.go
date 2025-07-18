package models

import (
	"time"
)

type CertificateEntry struct {
	Domain     string            `json:"domain"`
	Subdomains []string          `json:"subdomains"`
	LeafCert   LeafCertificate   `json:"leaf_cert"`
	Chain      []ChainCert       `json:"chain"`
	Timestamp  time.Time         `json:"timestamp"`
	LogURL     string            `json:"log_url"`
	Index      uint64            `json:"index"`
	Extensions map[string]string `json:"extensions,omitempty"`
}

type LeafCertificate struct {
	Subject                 Subject    `json:"subject"`
	Extensions              Extensions `json:"extensions"`
	NotBefore               time.Time  `json:"not_before"`
	NotAfter                time.Time  `json:"not_after"`
	SerialNumber            string     `json:"serial_number"`
	Fingerprint             string     `json:"fingerprint"`
	IssuerDistinguishedName string     `json:"issuer_distinguished_name"`
}

type Subject struct {
	CommonName         string `json:"common_name"`
	Country            string `json:"country"`
	Organization       string `json:"organization"`
	OrganizationalUnit string `json:"organizational_unit"`
	Locality           string `json:"locality"`
	Province           string `json:"province"`
}

type Extensions struct {
	SubjectAltName         []string `json:"subject_alt_name"`
	KeyUsage               []string `json:"key_usage"`
	ExtendedKeyUsage       []string `json:"extended_key_usage"`
	CertificatePolicies    []string `json:"certificate_policies"`
	AuthorityKeyIdentifier string   `json:"authority_key_identifier"`
	SubjectKeyIdentifier   string   `json:"subject_key_identifier"`
	BasicConstraints       string   `json:"basic_constraints"`
	IssuerAlternativeName  []string `json:"issuer_alternative_name"`
}

type ChainCert struct {
	Subject                 Subject   `json:"subject"`
	IssuerDistinguishedName string    `json:"issuer_distinguished_name"`
	NotBefore               time.Time `json:"not_before"`
	NotAfter                time.Time `json:"not_after"`
	SerialNumber            string    `json:"serial_number"`
}

type DomainWatch struct {
	Domain            string    `json:"domain"`
	IncludeSubdomains bool      `json:"include_subdomains"`
	CreatedAt         time.Time `json:"created_at"`
	LastSeen          time.Time `json:"last_seen"`
	Active            bool      `json:"active"`
}

type MonitoringConfig struct {
	WatchedDomains []DomainWatch `json:"watched_domains"`
	OutputPath     string        `json:"output_path"`
	OutputFormat   string        `json:"output_format"`
	LogLevel       string        `json:"log_level"`
}
