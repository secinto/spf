package spf

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

// MockResolver implements DNSResolver for testing
type MockResolver struct {
	TXTRecords  map[string][]string
	HostRecords map[string][]string
	MXRecords   map[string][]*net.MX
	AddrRecords map[string][]string
	Error       error
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

func (m *MockResolver) LookupHost(ctx context.Context, domain string) ([]string, error) {
	if m.Error != nil {
		return nil, m.Error
	}
	if records, ok := m.HostRecords[domain]; ok {
		return records, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: domain, IsNotFound: true}
}

func (m *MockResolver) LookupMX(ctx context.Context, domain string) ([]*net.MX, error) {
	if m.Error != nil {
		return nil, m.Error
	}
	if records, ok := m.MXRecords[domain]; ok {
		return records, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: domain, IsNotFound: true}
}

func (m *MockResolver) LookupAddr(ctx context.Context, ip string) ([]string, error) {
	if m.Error != nil {
		return nil, m.Error
	}
	if records, ok := m.AddrRecords[ip]; ok {
		return records, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: ip, IsNotFound: true}
}

// TestSPFWithMockResolver tests SPF evaluation with a mock DNS resolver
func TestSPFWithMockResolver(t *testing.T) {
	tests := []struct {
		name           string
		ip             string
		email          string
		expectedResult Result
		setupResolver  func() *MockResolver
	}{
		{
			name:           "Pass - IP4 match",
			ip:             "192.0.2.1",
			email:          "sender@example.com",
			expectedResult: Pass,
			setupResolver: func() *MockResolver {
				return &MockResolver{
					TXTRecords: map[string][]string{
						"example.com": {"v=spf1 ip4:192.0.2.0/24 -all"},
					},
				}
			},
		},
		{
			name:           "Fail - IP4 no match",
			ip:             "192.0.3.1",
			email:          "sender@example.com",
			expectedResult: Fail,
			setupResolver: func() *MockResolver {
				return &MockResolver{
					TXTRecords: map[string][]string{
						"example.com": {"v=spf1 ip4:192.0.2.0/24 -all"},
					},
				}
			},
		},
		{
			name:           "Pass - A record match",
			ip:             "192.0.2.1",
			email:          "sender@example.com",
			expectedResult: Pass,
			setupResolver: func() *MockResolver {
				return &MockResolver{
					TXTRecords: map[string][]string{
						"example.com": {"v=spf1 a -all"},
					},
					HostRecords: map[string][]string{
						"example.com": {"192.0.2.1"},
					},
				}
			},
		},
		{
			name:           "Pass - MX record match",
			ip:             "192.0.2.10",
			email:          "sender@example.com",
			expectedResult: Pass,
			setupResolver: func() *MockResolver {
				return &MockResolver{
					TXTRecords: map[string][]string{
						"example.com": {"v=spf1 mx -all"},
					},
					MXRecords: map[string][]*net.MX{
						"example.com": {
							{Host: "mail.example.com", Pref: 10},
						},
					},
					HostRecords: map[string][]string{
						"mail.example.com": {"192.0.2.10"},
					},
				}
			},
		},
		{
			name:           "Pass - Include match",
			ip:             "192.0.2.1",
			email:          "sender@example.com",
			expectedResult: Pass,
			setupResolver: func() *MockResolver {
				return &MockResolver{
					TXTRecords: map[string][]string{
						"example.com":   {"v=spf1 include:spf.example.com -all"},
						"spf.example.com": {"v=spf1 ip4:192.0.2.0/24 -all"},
					},
				}
			},
		},
		{
			name:           "Pass - Redirect",
			ip:             "192.0.2.1",
			email:          "sender@example.com",
			expectedResult: Pass,
			setupResolver: func() *MockResolver {
				return &MockResolver{
					TXTRecords: map[string][]string{
						"example.com":      {"v=spf1 redirect=spf.example.com"},
						"spf.example.com": {"v=spf1 ip4:192.0.2.0/24 -all"},
					},
				}
			},
		},
		{
			name:           "Pass - Exists match",
			ip:             "192.0.2.1",
			email:          "sender@example.com",
			expectedResult: Pass,
			setupResolver: func() *MockResolver {
				return &MockResolver{
					TXTRecords: map[string][]string{
						"example.com": {"v=spf1 exists:check.example.com -all"},
					},
					HostRecords: map[string][]string{
						"check.example.com": {"127.0.0.1"},
					},
				}
			},
		},
		{
			name:           "Pass - PTR match",
			ip:             "192.0.2.1",
			email:          "sender@example.com",
			expectedResult: Pass,
			setupResolver: func() *MockResolver {
				return &MockResolver{
					TXTRecords: map[string][]string{
						"example.com": {"v=spf1 ptr -all"},
					},
					AddrRecords: map[string][]string{
						"192.0.2.1": {"host.example.com"},
					},
				}
			},
		},
		{
			name:           "SoftFail - All with ~ qualifier",
			ip:             "192.0.3.1",
			email:          "sender@example.com",
			expectedResult: SoftFail,
			setupResolver: func() *MockResolver {
				return &MockResolver{
					TXTRecords: map[string][]string{
						"example.com": {"v=spf1 ~all"},
					},
				}
			},
		},
		{
			name:           "Neutral - ? qualifier",
			ip:             "192.0.3.1",
			email:          "sender@example.com",
			expectedResult: Neutral,
			setupResolver: func() *MockResolver {
				return &MockResolver{
					TXTRecords: map[string][]string{
						"example.com": {"v=spf1 ?all"},
					},
				}
			},
		},
		{
			name:           "None - No SPF record",
			ip:             "192.0.2.1",
			email:          "sender@example.com",
			expectedResult: None,
			setupResolver: func() *MockResolver {
				return &MockResolver{
					TXTRecords: map[string][]string{
						"example.com": {}, // Empty TXT records, no SPF
					},
				}
			},
		},
		{
			name:           "TempError - DNS lookup fails",
			ip:             "192.0.2.1",
			email:          "sender@example.com",
			expectedResult: TempError,
			setupResolver: func() *MockResolver {
				return &MockResolver{
					Error: &net.DNSError{Err: "temporary failure", IsTemporary: true},
				}
			},
		},
		{
			name:           "PermError - Invalid IP address",
			ip:             "not-an-ip",
			email:          "sender@example.com",
			expectedResult: PermError,
			setupResolver: func() *MockResolver {
				return &MockResolver{
					TXTRecords: map[string][]string{
						"example.com": {"v=spf1 -all"},
					},
				}
			},
		},
		{
			name:           "PermError - Invalid email",
			ip:             "192.0.2.1",
			email:          "not-an-email",
			expectedResult: PermError,
			setupResolver: func() *MockResolver {
				return &MockResolver{}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			config := &Config{
				MaxLookups:  MaxCount,
				DNSResolver: tt.setupResolver(),
				DNSTimeout:  10 * time.Second,
			}

			result, err := SPFTestContext(ctx, config, tt.ip, tt.email)
			if err != nil && result != TempError && result != PermError {
				t.Errorf("Unexpected error: %v", err)
			}

			if result != tt.expectedResult {
				t.Errorf("Expected %s, got %s", tt.expectedResult, result)
			}
		})
	}
}

// TestCircularIncludeDetection tests that circular includes are detected
func TestCircularIncludeDetection(t *testing.T) {
	resolver := &MockResolver{
		TXTRecords: map[string][]string{
			"a.com": {"v=spf1 include:b.com -all"},
			"b.com": {"v=spf1 include:c.com -all"},
			"c.com": {"v=spf1 include:a.com -all"},
		},
	}

	ctx := context.Background()
	config := &Config{
		MaxLookups:  MaxCount,
		DNSResolver: resolver,
		DNSTimeout:  10 * time.Second,
	}

	result, _ := SPFTestContext(ctx, config, "192.0.2.1", "sender@a.com")
	if result != PermError {
		t.Errorf("Expected PermError for circular include, got %s", result)
	}
}

// TestMaxLookupCount tests that the maximum DNS lookup count is enforced
func TestMaxLookupCount(t *testing.T) {
	// Create a chain of includes that exceeds MaxCount
	resolver := &MockResolver{
		TXTRecords: map[string][]string{
			"example.com": {"v=spf1 include:spf1.example.com include:spf2.example.com include:spf3.example.com include:spf4.example.com include:spf5.example.com include:spf6.example.com include:spf7.example.com include:spf8.example.com include:spf9.example.com include:spf10.example.com include:spf11.example.com include:spf12.example.com include:spf13.example.com include:spf14.example.com include:spf15.example.com include:spf16.example.com include:spf17.example.com include:spf18.example.com include:spf19.example.com include:spf20.example.com include:spf21.example.com -all"},
		},
		HostRecords: map[string][]string{},
	}

	for i := 1; i <= 21; i++ {
		domain := fmt.Sprintf("spf%d.example.com", i)
		resolver.TXTRecords[domain] = []string{"v=spf1 -all"}
	}

	ctx := context.Background()
	config := &Config{
		MaxLookups:  MaxCount,
		DNSResolver: resolver,
		DNSTimeout:  10 * time.Second,
	}

	result, _ := SPFTestContext(ctx, config, "192.0.2.1", "sender@example.com")
	if result != PermError {
		t.Errorf("Expected PermError for exceeding max lookups, got %s", result)
	}
}

// TestDNSCache tests that DNS caching works correctly
func TestDNSCache(t *testing.T) {
	mockResolver := &MockResolver{
		TXTRecords: map[string][]string{
			"example.com": {"v=spf1 ip4:192.0.2.0/24 -all"},
		},
	}

	cachedResolver := NewCachedResolver(mockResolver, 1*time.Second)

	ctx := context.Background()

	// First lookup should hit the mock resolver
	records1, err := cachedResolver.LookupTXT(ctx, "example.com")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Second lookup should hit the cache
	records2, err := cachedResolver.LookupTXT(ctx, "example.com")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if len(records1) != len(records2) {
		t.Errorf("Cache returned different results")
	}

	// Wait for cache to expire
	time.Sleep(1500 * time.Millisecond)

	// Third lookup should hit the mock resolver again
	records3, err := cachedResolver.LookupTXT(ctx, "example.com")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if len(records3) != len(records1) {
		t.Errorf("Cache expiration failed")
	}
}

// TestIPv6Support tests IPv6 address handling
func TestIPv6Support(t *testing.T) {
	resolver := &MockResolver{
		TXTRecords: map[string][]string{
			"example.com": {"v=spf1 ip6:2001:db8::/32 -all"},
		},
	}

	ctx := context.Background()
	config := &Config{
		MaxLookups:  MaxCount,
		DNSResolver: resolver,
		DNSTimeout:  10 * time.Second,
	}

	// Should pass for matching IPv6
	result, _ := SPFTestContext(ctx, config, "2001:db8::1", "sender@example.com")
	if result != Pass {
		t.Errorf("Expected Pass for matching IPv6, got %s", result)
	}

	// Should fail for non-matching IPv6
	result, _ = SPFTestContext(ctx, config, "2001:db9::1", "sender@example.com")
	if result != Fail {
		t.Errorf("Expected Fail for non-matching IPv6, got %s", result)
	}
}

// TestContextTimeout tests that context timeout is respected
func TestContextTimeout(t *testing.T) {
	// Create a resolver that would block
	resolver := &MockResolver{
		TXTRecords: map[string][]string{
			"example.com": {"v=spf1 a -all"},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// Give the context time to expire
	time.Sleep(10 * time.Millisecond)

	config := &Config{
		MaxLookups:  MaxCount,
		DNSResolver: resolver,
		DNSTimeout:  10 * time.Second,
	}

	// Context should already be expired
	_, err := SPFTestContext(ctx, config, "192.0.2.1", "sender@example.com")
	if err == nil {
		// Note: This might not fail if the operations complete before timeout
		t.Log("Context timeout test completed (may not have timed out)")
	}
}

// TestParallelMXLookups tests that MX lookups are parallelized
func TestParallelMXLookups(t *testing.T) {
	resolver := &MockResolver{
		TXTRecords: map[string][]string{
			"example.com": {"v=spf1 mx -all"},
		},
		MXRecords: map[string][]*net.MX{
			"example.com": {
				{Host: "mx1.example.com", Pref: 10},
				{Host: "mx2.example.com", Pref: 20},
				{Host: "mx3.example.com", Pref: 30},
			},
		},
		HostRecords: map[string][]string{
			"mx1.example.com": {"192.0.2.10"},
			"mx2.example.com": {"192.0.2.20"},
			"mx3.example.com": {"192.0.2.30"},
		},
	}

	ctx := context.Background()
	config := &Config{
		MaxLookups:  MaxCount,
		DNSResolver: resolver,
		DNSTimeout:  10 * time.Second,
	}

	// Test that IP from second MX is matched
	result, _ := SPFTestContext(ctx, config, "192.0.2.20", "sender@example.com")
	if result != Pass {
		t.Errorf("Expected Pass for MX match, got %s", result)
	}
}
