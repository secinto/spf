package dmarc

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// MockResolver implements DNSResolver for testing
type MockResolver struct {
	TXTRecords map[string][]string
	Error      error
}

func (m *MockResolver) LookupTXT(ctx context.Context, domain string) ([]string, error) {
	if m.Error != nil {
		return nil, m.Error
	}
	if records, ok := m.TXTRecords[domain]; ok {
		return records, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: domain, IsNotFound: true}
}

func TestParseDMARCRecord(t *testing.T) {
	tests := []struct {
		name    string
		record  string
		domain  string
		want    *Record
		wantErr bool
	}{
		{
			name:   "minimal record",
			record: "v=DMARC1; p=none",
			domain: "example.com",
			want: &Record{
				Version:        "DMARC1",
				Policy:         PolicyNone,
				SubPolicy:      PolicyNone,
				SPFAlignment:   AlignmentRelaxed,
				DKIMAlignment:  AlignmentRelaxed,
				Percentage:     100,
				ReportInterval: 86400 * time.Second,
				ReportFormat:   "afrf",
				Domain:         "example.com",
			},
			wantErr: false,
		},
		{
			name:   "comprehensive record",
			record: "v=DMARC1; p=quarantine; sp=reject; aspf=s; adkim=r; pct=50; rua=mailto:dmarc@example.com; ruf=mailto:forensic@example.com; fo=1; ri=3600",
			domain: "example.com",
			want: &Record{
				Version:        "DMARC1",
				Policy:         PolicyQuarantine,
				SubPolicy:      PolicyReject,
				SPFAlignment:   AlignmentStrict,
				DKIMAlignment:  AlignmentRelaxed,
				Percentage:     50,
				ReportInterval: 3600 * time.Second,
				ReportFormat:   "afrf",
				Domain:         "example.com",
				AggregateReportURIs: []ReportURI{
					{Scheme: "mailto", URI: "mailto:dmarc@example.com"},
				},
				ForensicReportURIs: []ReportURI{
					{Scheme: "mailto", URI: "mailto:forensic@example.com"},
				},
				FailureOptions: FailureOptions{ReportSPFOrDKIMFailure: true},
			},
			wantErr: false,
		},
		{
			name:    "missing version",
			record:  "p=none",
			domain:  "example.com",
			wantErr: true,
		},
		{
			name:    "missing policy",
			record:  "v=DMARC1",
			domain:  "example.com",
			wantErr: true,
		},
		{
			name:    "invalid version",
			record:  "v=DMARC2; p=none",
			domain:  "example.com",
			wantErr: true,
		},
		{
			name:    "invalid policy",
			record:  "v=DMARC1; p=invalid",
			domain:  "example.com",
			wantErr: true,
		},
		{
			name:    "invalid alignment",
			record:  "v=DMARC1; p=none; aspf=invalid",
			domain:  "example.com",
			wantErr: true,
		},
		{
			name:    "invalid percentage",
			record:  "v=DMARC1; p=none; pct=101",
			domain:  "example.com",
			wantErr: true,
		},
		{
			name:   "multiple report URIs",
			record: "v=DMARC1; p=none; rua=mailto:dmarc1@example.com,mailto:dmarc2@example.com!10m",
			domain: "example.com",
			want: &Record{
				Version:        "DMARC1",
				Policy:         PolicyNone,
				SubPolicy:      PolicyNone,
				SPFAlignment:   AlignmentRelaxed,
				DKIMAlignment:  AlignmentRelaxed,
				Percentage:     100,
				ReportInterval: 86400 * time.Second,
				ReportFormat:   "afrf",
				Domain:         "example.com",
				AggregateReportURIs: []ReportURI{
					{Scheme: "mailto", URI: "mailto:dmarc1@example.com"},
					{Scheme: "mailto", URI: "mailto:dmarc2@example.com", MaxSize: 10 * 1024 * 1024},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.record, tt.domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			// Compare fields
			if got.Version != tt.want.Version {
				t.Errorf("Version = %v, want %v", got.Version, tt.want.Version)
			}
			if got.Policy != tt.want.Policy {
				t.Errorf("Policy = %v, want %v", got.Policy, tt.want.Policy)
			}
			if got.SubPolicy != tt.want.SubPolicy {
				t.Errorf("SubPolicy = %v, want %v", got.SubPolicy, tt.want.SubPolicy)
			}
			if got.SPFAlignment != tt.want.SPFAlignment {
				t.Errorf("SPFAlignment = %v, want %v", got.SPFAlignment, tt.want.SPFAlignment)
			}
			if got.DKIMAlignment != tt.want.DKIMAlignment {
				t.Errorf("DKIMAlignment = %v, want %v", got.DKIMAlignment, tt.want.DKIMAlignment)
			}
			if got.Percentage != tt.want.Percentage {
				t.Errorf("Percentage = %v, want %v", got.Percentage, tt.want.Percentage)
			}
		})
	}
}

func TestLookupDMARC(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		resolver *MockResolver
		wantErr  bool
	}{
		{
			name:   "found at exact domain",
			domain: "example.com",
			resolver: &MockResolver{
				TXTRecords: map[string][]string{
					"_dmarc.example.com": {"v=DMARC1; p=none"},
				},
			},
			wantErr: false,
		},
		{
			name:   "found at organizational domain",
			domain: "mail.example.com",
			resolver: &MockResolver{
				TXTRecords: map[string][]string{
					"_dmarc.example.com": {"v=DMARC1; p=quarantine"},
				},
			},
			wantErr: false,
		},
		{
			name:   "not found",
			domain: "nonexistent.com",
			resolver: &MockResolver{
				TXTRecords: map[string][]string{},
			},
			wantErr: true,
		},
		{
			name:   "multiple records error",
			domain: "example.com",
			resolver: &MockResolver{
				TXTRecords: map[string][]string{
					"_dmarc.example.com": {
						"v=DMARC1; p=none",
						"v=DMARC1; p=reject",
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			got, err := Lookup(ctx, tt.resolver, tt.domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("Lookup() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got == nil {
				t.Error("Lookup() returned nil record")
			}
		})
	}
}

func TestCheckSPFAlignment(t *testing.T) {
	tests := []struct {
		name             string
		mailFromDomain   string
		headerFromDomain string
		mode             Alignment
		want             bool
	}{
		{
			name:             "exact match - relaxed",
			mailFromDomain:   "example.com",
			headerFromDomain: "example.com",
			mode:             AlignmentRelaxed,
			want:             true,
		},
		{
			name:             "exact match - strict",
			mailFromDomain:   "example.com",
			headerFromDomain: "example.com",
			mode:             AlignmentStrict,
			want:             true,
		},
		{
			name:             "subdomain match - relaxed",
			mailFromDomain:   "mail.example.com",
			headerFromDomain: "example.com",
			mode:             AlignmentRelaxed,
			want:             true,
		},
		{
			name:             "subdomain match - strict",
			mailFromDomain:   "mail.example.com",
			headerFromDomain: "example.com",
			mode:             AlignmentStrict,
			want:             false,
		},
		{
			name:             "different domain",
			mailFromDomain:   "other.com",
			headerFromDomain: "example.com",
			mode:             AlignmentRelaxed,
			want:             false,
		},
		{
			name:             "case insensitive",
			mailFromDomain:   "Example.COM",
			headerFromDomain: "example.com",
			mode:             AlignmentStrict,
			want:             true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckSPFAlignment(tt.mailFromDomain, tt.headerFromDomain, tt.mode)
			if got != tt.want {
				t.Errorf("CheckSPFAlignment() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckDKIMAlignment(t *testing.T) {
	tests := []struct {
		name             string
		dkimDomain       string
		headerFromDomain string
		mode             Alignment
		want             bool
	}{
		{
			name:             "exact match - relaxed",
			dkimDomain:       "example.com",
			headerFromDomain: "example.com",
			mode:             AlignmentRelaxed,
			want:             true,
		},
		{
			name:             "exact match - strict",
			dkimDomain:       "example.com",
			headerFromDomain: "example.com",
			mode:             AlignmentStrict,
			want:             true,
		},
		{
			name:             "subdomain match - relaxed",
			dkimDomain:       "selector._domainkey.example.com",
			headerFromDomain: "example.com",
			mode:             AlignmentRelaxed,
			want:             true,
		},
		{
			name:             "subdomain match - strict",
			dkimDomain:       "selector._domainkey.example.com",
			headerFromDomain: "example.com",
			mode:             AlignmentStrict,
			want:             false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckDKIMAlignment(tt.dkimDomain, tt.headerFromDomain, tt.mode)
			if got != tt.want {
				t.Errorf("CheckDKIMAlignment() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEvaluate(t *testing.T) {
	tests := []struct {
		name        string
		fromHeader  string
		mailFrom    string
		spfPass     bool
		dkimDomains []string
		resolver    *MockResolver
		wantPass    bool
		wantPolicy  Policy
	}{
		{
			name:        "SPF aligned - pass",
			fromHeader:  "sender@example.com",
			mailFrom:    "bounce@example.com",
			spfPass:     true,
			dkimDomains: []string{},
			resolver: &MockResolver{
				TXTRecords: map[string][]string{
					"_dmarc.example.com": {"v=DMARC1; p=quarantine"},
				},
			},
			wantPass:   true,
			wantPolicy: PolicyQuarantine,
		},
		{
			name:        "DKIM aligned - pass",
			fromHeader:  "sender@example.com",
			mailFrom:    "bounce@other.com",
			spfPass:     false,
			dkimDomains: []string{"example.com"},
			resolver: &MockResolver{
				TXTRecords: map[string][]string{
					"_dmarc.example.com": {"v=DMARC1; p=reject"},
				},
			},
			wantPass:   true,
			wantPolicy: PolicyReject,
		},
		{
			name:        "both aligned - pass",
			fromHeader:  "sender@example.com",
			mailFrom:    "bounce@example.com",
			spfPass:     true,
			dkimDomains: []string{"example.com"},
			resolver: &MockResolver{
				TXTRecords: map[string][]string{
					"_dmarc.example.com": {"v=DMARC1; p=reject"},
				},
			},
			wantPass:   true,
			wantPolicy: PolicyReject,
		},
		{
			name:        "neither aligned - fail",
			fromHeader:  "sender@example.com",
			mailFrom:    "bounce@other.com",
			spfPass:     false,
			dkimDomains: []string{"different.com"},
			resolver: &MockResolver{
				TXTRecords: map[string][]string{
					"_dmarc.example.com": {"v=DMARC1; p=reject"},
				},
			},
			wantPass:   false,
			wantPolicy: PolicyReject,
		},
		{
			name:        "no DMARC record",
			fromHeader:  "sender@example.com",
			mailFrom:    "bounce@example.com",
			spfPass:     true,
			dkimDomains: []string{},
			resolver: &MockResolver{
				TXTRecords: map[string][]string{},
			},
			wantPass:   false,
			wantPolicy: PolicyNone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			config := &Config{
				Resolver:        tt.resolver,
				CheckSubdomains: true,
				HonorSampling:   false,
				DNSTimeout:      10 * time.Second,
			}

			result, err := Evaluate(ctx, config, tt.fromHeader, tt.mailFrom, tt.spfPass, tt.dkimDomains)
			if err != nil {
				if err == ErrNoRecord {
					// Expected for "no DMARC record" test
					if tt.name != "no DMARC record" {
						t.Errorf("Evaluate() unexpected error = %v", err)
					}
					return
				}
				t.Errorf("Evaluate() error = %v", err)
				return
			}

			if result.Pass != tt.wantPass {
				t.Errorf("Evaluate() Pass = %v, want %v", result.Pass, tt.wantPass)
			}
			if result.AppliedPolicy != tt.wantPolicy {
				t.Errorf("Evaluate() AppliedPolicy = %v, want %v", result.AppliedPolicy, tt.wantPolicy)
			}
		})
	}
}

func TestParseSizeLimit(t *testing.T) {
	tests := []struct {
		name     string
		sizeStr  string
		expected int64
	}{
		{"10 kilobytes", "10k", 10 * 1024},
		{"50 megabytes", "50m", 50 * 1024 * 1024},
		{"1 gigabyte", "1g", 1 * 1024 * 1024 * 1024},
		{"empty string", "", 0},
		{"no suffix", "100", 100},
		{"uppercase K", "10K", 10 * 1024},
		{"uppercase M", "50M", 50 * 1024 * 1024},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseSizeLimit(tt.sizeStr)
			if got != tt.expected {
				t.Errorf("parseSizeLimit(%q) = %v, want %v", tt.sizeStr, got, tt.expected)
			}
		})
	}
}

func TestExtractOrganizationalDomain(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		expected string
	}{
		{"simple domain", "example.com", "example.com"},
		{"subdomain", "mail.example.com", "example.com"},
		{"deep subdomain", "a.b.c.example.com", "example.com"},
		{"co.uk domain", "example.co.uk", "example.co.uk"},
		{"subdomain of co.uk", "mail.example.co.uk", "example.co.uk"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := extractOrganizationalDomain(tt.domain)
			if !strings.EqualFold(got, tt.expected) {
				t.Errorf("extractOrganizationalDomain(%q) = %q, want %q", tt.domain, got, tt.expected)
			}
		})
	}
}

func TestIsSubdomain(t *testing.T) {
	tests := []struct {
		domain       string
		parentDomain string
		expected     bool
	}{
		{"mail.example.com", "example.com", true},
		{"a.b.example.com", "example.com", true},
		{"example.com", "example.com", false},
		{"other.com", "example.com", false},
		{"example.com", "mail.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.domain+" vs "+tt.parentDomain, func(t *testing.T) {
			got := isSubdomain(tt.domain, tt.parentDomain)
			if got != tt.expected {
				t.Errorf("isSubdomain(%q, %q) = %v, want %v", tt.domain, tt.parentDomain, got, tt.expected)
			}
		})
	}
}
