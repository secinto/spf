// Package dmarc implements RFC 7489 (Domain-based Message Authentication,
// Reporting, and Conformance) for validating DMARC policies and performing
// email authentication checks.
//
// DMARC builds on SPF and DKIM to provide domain-level authentication and
// reporting capabilities. It allows domain owners to specify policies for
// handling unauthenticated messages.
//
// Example usage:
//
//	ctx := context.Background()
//	resolver := spf.NewDefaultResolver()
//
//	// Lookup DMARC record
//	record, err := dmarc.Lookup(ctx, resolver, "example.com")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Evaluate policy
//	result, err := dmarc.Evaluate(ctx, config, message, spfResult, dkimResults)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	if result.Pass {
//	    // Accept message
//	}
package dmarc

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

// Policy represents a DMARC policy directive
type Policy string

const (
	// PolicyNone indicates no action should be taken
	PolicyNone Policy = "none"
	// PolicyQuarantine indicates the message should be quarantined
	PolicyQuarantine Policy = "quarantine"
	// PolicyReject indicates the message should be rejected
	PolicyReject Policy = "reject"
)

// Alignment represents identifier alignment mode
type Alignment string

const (
	// AlignmentRelaxed allows organizational domain match (default)
	AlignmentRelaxed Alignment = "r"
	// AlignmentStrict requires exact domain match
	AlignmentStrict Alignment = "s"
)

// Disposition represents the action to take based on DMARC evaluation
type Disposition string

const (
	// DispositionNone indicates no action
	DispositionNone Disposition = "none"
	// DispositionQuarantine indicates message should be quarantined
	DispositionQuarantine Disposition = "quarantine"
	// DispositionReject indicates message should be rejected
	DispositionReject Disposition = "reject"
)

// ReportURI represents a URI for DMARC reports
type ReportURI struct {
	Scheme  string // mailto or https
	URI     string // Full URI
	MaxSize int64  // Size limit in bytes (0 = no limit)
}

// FailureOptions represents failure reporting options
type FailureOptions struct {
	ReportAll              bool // fo=0 (default)
	ReportSPFOrDKIMFailure bool // fo=1
	ReportDKIMFailure      bool // fo=d
	ReportSPFFailure       bool // fo=s
}

// Record represents a parsed DMARC record
type Record struct {
	// Required fields
	Version string // v=DMARC1

	// Policy fields
	Policy    Policy // p=none|quarantine|reject
	SubPolicy Policy // sp=none|quarantine|reject (defaults to p value)

	// Alignment modes
	SPFAlignment  Alignment // aspf=r|s (default: r)
	DKIMAlignment Alignment // adkim=r|s (default: r)

	// Sampling
	Percentage int // pct=0-100 (default: 100)

	// Reporting
	AggregateReportURIs []ReportURI   // rua=mailto:...
	ForensicReportURIs  []ReportURI   // ruf=mailto:...
	ReportFormat        string        // rf=afrf (default)
	ReportInterval      time.Duration // ri=86400 (seconds, default: 86400)

	// Options
	FailureOptions FailureOptions // fo=0|1|d|s (default: 0)

	// Metadata
	Raw    string // Original DNS record
	Domain string // Domain this record applies to
}

// Result represents the outcome of DMARC evaluation
type Result struct {
	// Overall result
	Pass bool

	// Component results
	SPFResult   interface{} // spf.Result (use interface{} to avoid circular dependency)
	SPFAligned  bool
	DKIMResults []interface{} // []dkim.Result
	DKIMAligned bool

	// Policy decision
	AppliedPolicy Policy
	Disposition   Disposition

	// Details
	Reason []string
	Record *Record

	// RFC 5322.From domain
	From string

	// Metadata
	EvaluatedAt time.Time
}

// DNSResolver interface for DNS lookups (matches spf.DNSResolver)
type DNSResolver interface {
	LookupTXT(ctx context.Context, domain string) ([]string, error)
}

// Config holds DMARC evaluation configuration
type Config struct {
	// DNS resolver
	Resolver DNSResolver

	// Enable subdomain policy checking
	CheckSubdomains bool

	// Honor percentage sampling
	HonorSampling bool

	// Timeout for DNS lookups
	DNSTimeout time.Duration
}

// Errors
var (
	ErrNoRecord             = errors.New("no DMARC record found")
	ErrMultipleRecords      = errors.New("multiple DMARC records found")
	ErrInvalidVersion       = errors.New("invalid DMARC version")
	ErrInvalidPolicy        = errors.New("invalid policy value")
	ErrInvalidAlignment     = errors.New("invalid alignment mode")
	ErrInvalidPercentage    = errors.New("invalid percentage value")
	ErrInvalidInterval      = errors.New("invalid report interval")
	ErrInvalidFailureOption = errors.New("invalid failure reporting option")
	ErrMissingVersion       = errors.New("missing required version tag")
	ErrMissingPolicy        = errors.New("missing required policy tag")
	ErrInvalidTag           = errors.New("invalid tag format")
	ErrInvalidFrom          = errors.New("invalid From header")
	ErrInvalidURI           = errors.New("invalid report URI")
)

// Lookup performs DNS lookup for DMARC record
// Looks up _dmarc.domain TXT record
// Falls back to organizational domain if not found
func Lookup(ctx context.Context, resolver DNSResolver, domain string) (*Record, error) {
	// Try exact domain first
	record, err := lookupDMARCRecord(ctx, resolver, domain)
	if err == nil {
		return record, nil
	}

	if err != ErrNoRecord {
		return nil, err
	}

	// Try organizational domain
	orgDomain, _ := extractOrganizationalDomain(domain)

	if orgDomain != domain {
		return lookupDMARCRecord(ctx, resolver, orgDomain)
	}

	return nil, ErrNoRecord
}

// lookupDMARCRecord looks up DMARC record for a specific domain
func lookupDMARCRecord(ctx context.Context, resolver DNSResolver, domain string) (*Record, error) {
	dmarcDomain := "_dmarc." + domain

	records, err := resolver.LookupTXT(ctx, dmarcDomain)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			return nil, ErrNoRecord
		}
		return nil, err
	}

	// Find DMARC record (should be only one)
	var dmarcRecord string
	for _, record := range records {
		if strings.HasPrefix(record, "v=DMARC1") {
			if dmarcRecord != "" {
				return nil, ErrMultipleRecords
			}
			dmarcRecord = record
		}
	}

	if dmarcRecord == "" {
		return nil, ErrNoRecord
	}

	return Parse(dmarcRecord, domain)
}

// Parse parses a DMARC TXT record
func Parse(record string, domain string) (*Record, error) {
	r := &Record{
		Raw:            record,
		Domain:         domain,
		SPFAlignment:   AlignmentRelaxed,            // default
		DKIMAlignment:  AlignmentRelaxed,            // default
		Percentage:     100,                         // default
		ReportInterval: 86400 * time.Second,         // default
		ReportFormat:   "afrf",                      // default
		FailureOptions: FailureOptions{ReportAll: true}, // fo=0 is default
	}

	// Split into tag=value pairs
	pairs := strings.Split(record, ";")

	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 {
			// Ignore malformed tags per RFC
			continue
		}

		tag := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch tag {
		case "v":
			if value != "DMARC1" {
				return nil, ErrInvalidVersion
			}
			r.Version = value

		case "p":
			policy, err := parsePolicy(value)
			if err != nil {
				return nil, err
			}
			r.Policy = policy

		case "sp":
			policy, err := parsePolicy(value)
			if err != nil {
				return nil, err
			}
			r.SubPolicy = policy

		case "aspf":
			alignment, err := parseAlignment(value)
			if err != nil {
				return nil, err
			}
			r.SPFAlignment = alignment

		case "adkim":
			alignment, err := parseAlignment(value)
			if err != nil {
				return nil, err
			}
			r.DKIMAlignment = alignment

		case "pct":
			pct, err := strconv.Atoi(value)
			if err != nil || pct < 0 || pct > 100 {
				return nil, ErrInvalidPercentage
			}
			r.Percentage = pct

		case "rua":
			uris, err := parseReportURIs(value)
			if err != nil {
				return nil, err
			}
			r.AggregateReportURIs = uris

		case "ruf":
			uris, err := parseReportURIs(value)
			if err != nil {
				return nil, err
			}
			r.ForensicReportURIs = uris

		case "fo":
			options, err := parseFailureOptions(value)
			if err != nil {
				return nil, err
			}
			r.FailureOptions = options

		case "ri":
			seconds, err := strconv.ParseInt(value, 10, 64)
			if err != nil || seconds < 0 {
				return nil, ErrInvalidInterval
			}
			r.ReportInterval = time.Duration(seconds) * time.Second

		case "rf":
			r.ReportFormat = value

		// Unknown tags are ignored per RFC 7489
		}
	}

	// Validate required fields
	if r.Version == "" {
		return nil, ErrMissingVersion
	}
	if r.Policy == "" {
		return nil, ErrMissingPolicy
	}

	// Set sub-policy default to policy if not specified
	if r.SubPolicy == "" {
		r.SubPolicy = r.Policy
	}

	return r, nil
}

// parsePolicy parses a policy value
func parsePolicy(value string) (Policy, error) {
	switch value {
	case "none":
		return PolicyNone, nil
	case "quarantine":
		return PolicyQuarantine, nil
	case "reject":
		return PolicyReject, nil
	default:
		return "", ErrInvalidPolicy
	}
}

// parseAlignment parses an alignment mode
func parseAlignment(value string) (Alignment, error) {
	switch value {
	case "r":
		return AlignmentRelaxed, nil
	case "s":
		return AlignmentStrict, nil
	default:
		return "", ErrInvalidAlignment
	}
}

// parseReportURIs parses report URIs
func parseReportURIs(value string) ([]ReportURI, error) {
	// Format: mailto:user@domain.com!50m,https://example.com/dmarc
	uris := []ReportURI{}

	parts := strings.Split(value, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Extract size limit if present
		var uri string
		var maxSize int64

		if idx := strings.Index(part, "!"); idx != -1 {
			uri = part[:idx]
			sizeStr := part[idx+1:]

			// Parse size (e.g., "50m", "10k", "1g")
			maxSize = parseSizeLimit(sizeStr)
		} else {
			uri = part
		}

		// Validate URI format
		if !strings.Contains(uri, ":") {
			return nil, ErrInvalidURI
		}

		schemeEnd := strings.Index(uri, ":")
		scheme := uri[:schemeEnd]

		uris = append(uris, ReportURI{
			Scheme:  scheme,
			URI:     uri,
			MaxSize: maxSize,
		})
	}

	return uris, nil
}

// parseSizeLimit parses size limit strings like "50m", "10k", "1g"
func parseSizeLimit(sizeStr string) int64 {
	if sizeStr == "" {
		return 0
	}

	// Get the last character
	lastChar := sizeStr[len(sizeStr)-1]
	var multiplier int64 = 1

	switch lastChar {
	case 'k', 'K':
		multiplier = 1024
		sizeStr = sizeStr[:len(sizeStr)-1]
	case 'm', 'M':
		multiplier = 1024 * 1024
		sizeStr = sizeStr[:len(sizeStr)-1]
	case 'g', 'G':
		multiplier = 1024 * 1024 * 1024
		sizeStr = sizeStr[:len(sizeStr)-1]
	case 't', 'T':
		multiplier = 1024 * 1024 * 1024 * 1024
		sizeStr = sizeStr[:len(sizeStr)-1]
	}

	size, err := strconv.ParseInt(sizeStr, 10, 64)
	if err != nil {
		return 0
	}

	return size * multiplier
}

// parseFailureOptions parses failure reporting options
func parseFailureOptions(value string) (FailureOptions, error) {
	opts := FailureOptions{}

	parts := strings.Split(value, ":")
	for _, part := range parts {
		switch part {
		case "0":
			opts.ReportAll = true
		case "1":
			opts.ReportSPFOrDKIMFailure = true
		case "d":
			opts.ReportDKIMFailure = true
		case "s":
			opts.ReportSPFFailure = true
		default:
			return opts, ErrInvalidFailureOption
		}
	}

	return opts, nil
}

// extractOrganizationalDomain extracts the organizational domain
// from a fully qualified domain name using the Public Suffix List
func extractOrganizationalDomain(domain string) (string, error) {
	domain = strings.ToLower(domain)

	// EffectiveTLDPlusOne returns the organizational domain
	orgDomain, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return domain, nil // fallback to original domain
	}

	return orgDomain, nil
}

// CheckSPFAlignment determines if SPF identifier is aligned
func CheckSPFAlignment(mailFromDomain, headerFromDomain string, mode Alignment) bool {
	if mode == AlignmentStrict {
		// Strict: exact match required
		return strings.EqualFold(mailFromDomain, headerFromDomain)
	}

	// Relaxed: organizational domain match
	mailFromOrg, _ := extractOrganizationalDomain(mailFromDomain)
	headerFromOrg, _ := extractOrganizationalDomain(headerFromDomain)

	return strings.EqualFold(mailFromOrg, headerFromOrg)
}

// CheckDKIMAlignment determines if DKIM signature is aligned
func CheckDKIMAlignment(dkimDomain, headerFromDomain string, mode Alignment) bool {
	if mode == AlignmentStrict {
		// Strict: exact match required
		return strings.EqualFold(dkimDomain, headerFromDomain)
	}

	// Relaxed: organizational domain match
	dkimOrg, _ := extractOrganizationalDomain(dkimDomain)
	headerFromOrg, _ := extractOrganizationalDomain(headerFromDomain)

	return strings.EqualFold(dkimOrg, headerFromOrg)
}

// policyToDisposition converts a policy to a disposition
func policyToDisposition(policy Policy) Disposition {
	switch policy {
	case PolicyNone:
		return DispositionNone
	case PolicyQuarantine:
		return DispositionQuarantine
	case PolicyReject:
		return DispositionReject
	default:
		return DispositionNone
	}
}

// shouldSample determines if a message should be sampled based on percentage
func shouldSample(percentage int) bool {
	if percentage >= 100 {
		return true
	}
	if percentage <= 0 {
		return false
	}
	// Use random number for sampling
	return rand.Intn(100) < percentage
}

// isSubdomain checks if domain is a subdomain of parentDomain
func isSubdomain(domain, parentDomain string) bool {
	if domain == parentDomain {
		return false
	}
	return strings.HasSuffix(strings.ToLower(domain), "."+strings.ToLower(parentDomain))
}

// EvaluateResult is a simplified version for demonstration
// Full implementation would need message details and SPF/DKIM results
type EvaluateResult struct {
	Pass            bool
	SPFAligned      bool
	DKIMAligned     bool
	AppliedPolicy   Policy
	Disposition     Disposition
	Reason          []string
	From            string
	MailFromDomain  string
	HeaderFromDomain string
	EvaluatedAt     time.Time
}

// Evaluate performs DMARC policy evaluation given SPF and DKIM results
// This is a core function that combines authentication results
func Evaluate(ctx context.Context, config *Config, fromHeader, mailFrom string,
	spfPass bool, dkimDomains []string) (*EvaluateResult, error) {

	result := &EvaluateResult{
		EvaluatedAt: time.Now(),
		From:        fromHeader,
	}

	// Extract RFC 5322.From domain
	addr, err := mail.ParseAddress(fromHeader)
	if err != nil {
		return nil, ErrInvalidFrom
	}
	parts := strings.Split(addr.Address, "@")
	if len(parts) != 2 {
		return nil, ErrInvalidFrom
	}
	headerFromDomain := parts[1]
	result.HeaderFromDomain = headerFromDomain

	// Extract mail from domain
	if strings.Contains(mailFrom, "@") {
		mailParts := strings.Split(mailFrom, "@")
		if len(mailParts) == 2 {
			result.MailFromDomain = mailParts[1]
		}
	}

	// Lookup DMARC record
	record, err := Lookup(ctx, config.Resolver, headerFromDomain)
	if err != nil {
		if err == ErrNoRecord {
			// No DMARC record = no policy
			result.Pass = false
			result.AppliedPolicy = PolicyNone
			result.Disposition = DispositionNone
			result.Reason = append(result.Reason, "no DMARC record")
			return result, nil
		}
		return nil, err
	}

	// Check SPF alignment
	if spfPass && result.MailFromDomain != "" {
		result.SPFAligned = CheckSPFAlignment(
			result.MailFromDomain,
			headerFromDomain,
			record.SPFAlignment,
		)
	}

	// Check DKIM alignment
	for _, dkimDomain := range dkimDomains {
		if CheckDKIMAlignment(dkimDomain, headerFromDomain, record.DKIMAlignment) {
			result.DKIMAligned = true
			break
		}
	}

	// Determine pass/fail
	// DMARC passes if either SPF or DKIM is aligned
	result.Pass = result.SPFAligned || result.DKIMAligned

	// Determine policy to apply
	policy := record.Policy
	if isSubdomain(headerFromDomain, record.Domain) {
		policy = record.SubPolicy
	}
	result.AppliedPolicy = policy

	// Apply sampling
	if config.HonorSampling {
		if shouldSample(record.Percentage) {
			result.Disposition = policyToDisposition(policy)
		} else {
			result.Disposition = DispositionNone
			result.Reason = append(result.Reason, "sampled out")
		}
	} else {
		result.Disposition = policyToDisposition(policy)
	}

	// If DMARC passes, override disposition
	if result.Pass {
		result.Disposition = DispositionNone
	}

	// Add reasons for failure
	if !result.Pass {
		if !result.SPFAligned {
			result.Reason = append(result.Reason, "SPF not aligned")
		}
		if !result.DKIMAligned {
			result.Reason = append(result.Reason, "DKIM not aligned")
		}
	}

	return result, nil
}
