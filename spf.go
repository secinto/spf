// Package spf can parse an SPF record and determine if a given IP address is
// allowed to send email based on that record. SPF can handle all of the
// mechanisms defined at http://www.openspf.org/SPF_Record_Syntax, including
// redirect, include, exists, a, mx, ptr, ip4, ip6, and all.
//
// The package implements RFC 7208 (Sender Policy Framework) with support for:
//   - DNS caching with configurable TTL
//   - Context-based timeouts and cancellation
//   - Pluggable DNS resolvers for testing
//   - Circular include detection
//   - Parallel MX record lookups
//   - Proper error handling and reporting
//
// Example usage:
//
//	result, err := spf.SPFTest("192.0.2.1", "sender@example.com")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	switch result {
//	case spf.Pass:
//	    // Allow email
//	case spf.Fail:
//	    // Reject email
//	case spf.SoftFail:
//	    // Accept but mark
//	case spf.Neutral, spf.None:
//	    // No policy
//	case spf.TempError:
//	    // Temporary DNS failure, try again later
//	case spf.PermError:
//	    // Permanent error in SPF record
//	}
package spf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"strings"
	"sync"
	"time"
)

const (
	// MaxCount is the maximum number of DNS lookups allowed per SPF evaluation
	// as defined by RFC 7208 section 4.6.4
	MaxCount = 20

	// DefaultIPv4Prefix is the default CIDR prefix for IPv4 addresses
	DefaultIPv4Prefix = "32"

	// DefaultIPv6Prefix is the default CIDR prefix for IPv6 addresses
	DefaultIPv6Prefix = "128"

	// DefaultCacheTTL is the default time-to-live for DNS cache entries
	DefaultCacheTTL = 5 * time.Minute

	// DefaultDNSTimeout is the default timeout for DNS lookups
	DefaultDNSTimeout = 10 * time.Second
)

var (
	ErrNoRecord         = errors.New("no SPF record found")
	ErrFailedLookup     = errors.New("DNS lookup failed")
	ErrInvalidSPF       = errors.New("invalid SPF string")
	ErrIncludeLoop      = errors.New("include loop detected")
	ErrInvalidMechanism = errors.New("invalid mechanism in SPF string")
	ErrMaxCount         = errors.New("exceeded maximum lookups")
	ErrInvalidEmail     = errors.New("invalid email address")
	ErrInvalidIP        = errors.New("invalid IP address")
)

// DNSResolver is an interface for DNS lookups, allowing for custom implementations
// including mocking for tests and adding caching layers
type DNSResolver interface {
	LookupTXT(ctx context.Context, domain string) ([]string, error)
	LookupHost(ctx context.Context, domain string) ([]string, error)
	LookupMX(ctx context.Context, domain string) ([]*net.MX, error)
	LookupAddr(ctx context.Context, ip string) ([]string, error)
}

// DefaultResolver implements DNSResolver using net package
type DefaultResolver struct {
	resolver *net.Resolver
}

// NewDefaultResolver creates a new default DNS resolver
func NewDefaultResolver() *DefaultResolver {
	return &DefaultResolver{
		resolver: net.DefaultResolver,
	}
}

func (r *DefaultResolver) LookupTXT(ctx context.Context, domain string) ([]string, error) {
	return r.resolver.LookupTXT(ctx, domain)
}

func (r *DefaultResolver) LookupHost(ctx context.Context, domain string) ([]string, error) {
	return r.resolver.LookupHost(ctx, domain)
}

func (r *DefaultResolver) LookupMX(ctx context.Context, domain string) ([]*net.MX, error) {
	return r.resolver.LookupMX(ctx, domain)
}

func (r *DefaultResolver) LookupAddr(ctx context.Context, ip string) ([]string, error) {
	return r.resolver.LookupAddr(ctx, ip)
}

// cacheEntry represents a cached DNS result with expiration
type cacheEntry struct {
	value      interface{}
	expiration time.Time
}

// DNSCache provides a simple in-memory cache for DNS lookups with TTL support
type DNSCache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
	ttl     time.Duration
}

// NewDNSCache creates a new DNS cache with the specified TTL
func NewDNSCache(ttl time.Duration) *DNSCache {
	cache := &DNSCache{
		entries: make(map[string]cacheEntry),
		ttl:     ttl,
	}
	// Start cleanup goroutine
	go cache.cleanup()
	return cache
}

func (c *DNSCache) get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[key]
	if !exists || time.Now().After(entry.expiration) {
		return nil, false
	}
	return entry.value, true
}

func (c *DNSCache) set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[key] = cacheEntry{
		value:      value,
		expiration: time.Now().Add(c.ttl),
	}
}

func (c *DNSCache) cleanup() {
	ticker := time.NewTicker(c.ttl)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for key, entry := range c.entries {
			if now.After(entry.expiration) {
				delete(c.entries, key)
			}
		}
		c.mu.Unlock()
	}
}

// CachedResolver wraps a DNSResolver with caching
type CachedResolver struct {
	resolver DNSResolver
	cache    *DNSCache
}

// NewCachedResolver creates a resolver with caching support
func NewCachedResolver(resolver DNSResolver, ttl time.Duration) *CachedResolver {
	return &CachedResolver{
		resolver: resolver,
		cache:    NewDNSCache(ttl),
	}
}

func (r *CachedResolver) LookupTXT(ctx context.Context, domain string) ([]string, error) {
	key := "txt:" + domain
	if cached, ok := r.cache.get(key); ok {
		return cached.([]string), nil
	}

	result, err := r.resolver.LookupTXT(ctx, domain)
	if err == nil {
		r.cache.set(key, result)
	}
	return result, err
}

func (r *CachedResolver) LookupHost(ctx context.Context, domain string) ([]string, error) {
	key := "host:" + domain
	if cached, ok := r.cache.get(key); ok {
		return cached.([]string), nil
	}

	result, err := r.resolver.LookupHost(ctx, domain)
	if err == nil {
		r.cache.set(key, result)
	}
	return result, err
}

func (r *CachedResolver) LookupMX(ctx context.Context, domain string) ([]*net.MX, error) {
	key := "mx:" + domain
	if cached, ok := r.cache.get(key); ok {
		return cached.([]*net.MX), nil
	}

	result, err := r.resolver.LookupMX(ctx, domain)
	if err == nil {
		r.cache.set(key, result)
	}
	return result, err
}

func (r *CachedResolver) LookupAddr(ctx context.Context, ip string) ([]string, error) {
	key := "addr:" + ip
	if cached, ok := r.cache.get(key); ok {
		return cached.([]string), nil
	}

	result, err := r.resolver.LookupAddr(ctx, ip)
	if err == nil {
		r.cache.set(key, result)
	}
	return result, err
}

// Config holds configuration options for SPF checking
type Config struct {
	// MaxLookups is the maximum number of DNS lookups allowed (default: MaxCount)
	MaxLookups int

	// DNSResolver is the resolver to use for DNS lookups (default: DefaultResolver)
	DNSResolver DNSResolver

	// EnableCache enables DNS caching (default: true)
	EnableCache bool

	// CacheTTL is the time-to-live for cache entries (default: DefaultCacheTTL)
	CacheTTL time.Duration

	// DNSTimeout is the timeout for DNS operations (default: DefaultDNSTimeout)
	DNSTimeout time.Duration
}

// DefaultConfig returns a Config with default values
func DefaultConfig() *Config {
	resolver := NewDefaultResolver()
	return &Config{
		MaxLookups:  MaxCount,
		DNSResolver: NewCachedResolver(resolver, DefaultCacheTTL),
		EnableCache: true,
		CacheTTL:    DefaultCacheTTL,
		DNSTimeout:  DefaultDNSTimeout,
	}
}

var defaultConfig = DefaultConfig()

// SPF represents an SPF record for a particular Domain. The SPF record
// holds all of the Allow, Deny, and Neutral mechanisms.
type SPF struct {
	Raw        string
	Domain     string
	Version    string
	Mechanisms []Mechanism
	Count      int
	resolver   DNSResolver
	ctx        context.Context
	visited    map[string]bool // Track visited domains to detect circular includes
}

// Test evaluates each mechanism to determine the result for the client.
// Mechanisms are evaluated in order until one of them provides a valid
// result. If no valid results are provided, the default result of "Neutral"
// is returned.
func (s *SPF) Test(ip string) Result {
	// Validate IP address
	if net.ParseIP(ip) == nil {
		return PermError
	}

	for _, m := range s.Mechanisms {
		result, err := m.EvaluateWithContext(s.ctx, s.resolver, ip, s.Count, s.visited)
		if err == nil {
			return result
		}
	}

	return Neutral
}

// Return an SPF record as a string.
func (s *SPF) String() string {
	var buf bytes.Buffer

	buf.WriteString(fmt.Sprintf("Raw: %s\n", s.Raw))
	buf.WriteString(fmt.Sprintf("Domain: %s\n", s.Domain))
	buf.WriteString(fmt.Sprintf("Version: %s\n", s.Version))

	buf.WriteString("Mechanisms:\n")
	for _, m := range s.Mechanisms {
		buf.WriteString(fmt.Sprintf("\t%s\n", m.String()))
	}

	return buf.String()
}

// SPFString returns a formatted SPF object as a string suitable for use in a
// TXT record.
func (s *SPF) SPFString() string {
	var buf bytes.Buffer

	buf.WriteString(fmt.Sprintf("v=%s", s.Version))
	for _, m := range s.Mechanisms {
		buf.WriteString(fmt.Sprintf(" %s", m.SPFString()))
	}

	return buf.String()
}

func getSPFRecord(ctx context.Context, resolver DNSResolver, domain string) (string, error) {
	var spfText string

	// DNS errors during domain name lookup should result in "TempError".
	records, err := resolver.LookupTXT(ctx, domain)
	if err != nil {
		return "", ErrFailedLookup
	}

	// Find the SPF record among the TXT records for the domain.
	for _, record := range records {
		if strings.HasPrefix(record, "v=spf1") {
			spfText = record
			break
		}
	}

	return spfText, nil
}

// NewSPFWithContext creates a new SPF record for the given domain using the provided string
// with context support for timeouts and custom resolver.
// If the provided string is not valid an error is returned.
func NewSPFWithContext(ctx context.Context, resolver DNSResolver, domain, record string, count int, visited map[string]bool) (SPF, error) {
	var spf SPF

	// Initialize visited map if nil
	if visited == nil {
		visited = make(map[string]bool)
	}

	// Check for circular include
	if visited[domain] {
		return spf, ErrIncludeLoop
	}

	// Mark this domain as visited
	visited[domain] = true

	if record == "" {
		spfText, err := getSPFRecord(ctx, resolver, domain)
		if err != nil {
			return spf, err
		}

		if spfText == "" {
			return spf, ErrNoRecord
		}

		record = spfText
	}

	spf.Count = count
	spf.Raw = record
	spf.Domain = domain
	spf.resolver = resolver
	spf.ctx = ctx
	spf.visited = visited

	if !strings.HasPrefix(record, "v=spf1") {
		return spf, ErrInvalidSPF
	}

	for _, f := range strings.Fields(record) {
		// Check MaxCount before adding more mechanisms to prevent DoS
		if spf.Count >= MaxCount {
			return spf, ErrMaxCount
		}

		switch {
		case strings.HasPrefix(f, "v="):
			spf.Version = f[2:]
		default:
			mechanism, err := NewMechanism(f, domain)

			if err != nil {
				return spf, err
			}

			if !mechanism.Valid() {
				return spf, ErrInvalidMechanism
			}

			// Check for direct self-reference in include/redirect
			if mechanism.Name == "include" && mechanism.Domain == domain {
				return spf, ErrIncludeLoop
			}
			if mechanism.Name == "redirect" && mechanism.Domain == domain {
				return spf, ErrIncludeLoop
			}

			switch mechanism.Name {
			case "include":
				spf.Count = spf.Count + 1
			case "redirect", "exists", "a", "mx", "ptr":
				spf.Count = spf.Count + 1
			default:
				// No action
			}

			spf.Mechanisms = append(spf.Mechanisms, mechanism)
		}
	}

	return spf, nil
}

// NewSPF creates a new SPF record for the given domain using the provided string.
// This function is kept for backward compatibility and uses default configuration.
// If the provided string is not valid an error is returned.
func NewSPF(domain, record string, count int) (SPF, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultConfig.DNSTimeout)
	defer cancel()

	return NewSPFWithContext(ctx, defaultConfig.DNSResolver, domain, record, count, nil)
}

/*
Exported functions.
*/

// SPFTestContext determines the client's sending status for the given email address
// with context support for timeouts and cancellation.
//
// SPFTestContext will return one of the following results:
// Pass, Fail, SoftFail, Neutral, None, TempError, or PermError
func SPFTestContext(ctx context.Context, config *Config, ip, email string) (Result, error) {
	// Validate IP address format
	if net.ParseIP(ip) == nil {
		return PermError, ErrInvalidIP
	}

	// Parse and validate email address using net/mail
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return PermError, ErrInvalidEmail
	}

	// Extract domain from validated email address
	parts := strings.Split(addr.Address, "@")
	if len(parts) != 2 || parts[1] == "" {
		return PermError, ErrInvalidEmail
	}
	domain := parts[1]

	// Use default config if none provided
	if config == nil {
		config = defaultConfig
	}

	// Create context with timeout if not already set
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, config.DNSTimeout)
		defer cancel()
	}

	spfText, err := getSPFRecord(ctx, config.DNSResolver, domain)
	if err != nil {
		return TempError, err
	}

	// No SPF record should result in None.
	if spfText == "" {
		return None, nil
	}

	// Create a new SPF struct
	spf, err := NewSPFWithContext(ctx, config.DNSResolver, domain, spfText, 0, nil)
	if err != nil {
		return PermError, err
	}

	return spf.Test(ip), nil
}

// SPFTest determines the client's sending status for the given email address.
// This function is kept for backward compatibility and uses default configuration.
//
// SPFTest will return one of the following results:
// Pass, Fail, SoftFail, Neutral, None, TempError, or PermError
func SPFTest(ip, email string) (Result, error) {
	return SPFTestContext(context.Background(), defaultConfig, ip, email)
}
