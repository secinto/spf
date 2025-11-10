package spf

import (
	"context"
	"net"
	"testing"
	"time"
)

// BenchmarkSPFTestIP4 benchmarks SPF evaluation with IP4 mechanisms
func BenchmarkSPFTestIP4(b *testing.B) {
	resolver := &MockResolver{
		TXTRecords: map[string][]string{
			"example.com": {"v=spf1 ip4:192.0.2.0/24 ip4:198.51.100.0/24 ip4:203.0.113.0/24 -all"},
		},
	}

	ctx := context.Background()
	config := &Config{
		MaxLookups:  MaxCount,
		DNSResolver: resolver,
		DNSTimeout:  10 * time.Second,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = SPFTestContext(ctx, config, "192.0.2.1", "sender@example.com")
	}
}

// BenchmarkSPFTestA benchmarks SPF evaluation with A mechanism
func BenchmarkSPFTestA(b *testing.B) {
	resolver := &MockResolver{
		TXTRecords: map[string][]string{
			"example.com": {"v=spf1 a -all"},
		},
		HostRecords: map[string][]string{
			"example.com": {"192.0.2.1", "192.0.2.2", "192.0.2.3"},
		},
	}

	ctx := context.Background()
	config := &Config{
		MaxLookups:  MaxCount,
		DNSResolver: resolver,
		DNSTimeout:  10 * time.Second,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = SPFTestContext(ctx, config, "192.0.2.1", "sender@example.com")
	}
}

// BenchmarkSPFTestMX benchmarks SPF evaluation with MX mechanism
func BenchmarkSPFTestMX(b *testing.B) {
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

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = SPFTestContext(ctx, config, "192.0.2.20", "sender@example.com")
	}
}

// BenchmarkSPFTestInclude benchmarks SPF evaluation with include mechanism
func BenchmarkSPFTestInclude(b *testing.B) {
	resolver := &MockResolver{
		TXTRecords: map[string][]string{
			"example.com":     {"v=spf1 include:spf1.example.com include:spf2.example.com -all"},
			"spf1.example.com": {"v=spf1 ip4:192.0.2.0/24 -all"},
			"spf2.example.com": {"v=spf1 ip4:198.51.100.0/24 -all"},
		},
	}

	ctx := context.Background()
	config := &Config{
		MaxLookups:  MaxCount,
		DNSResolver: resolver,
		DNSTimeout:  10 * time.Second,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = SPFTestContext(ctx, config, "192.0.2.1", "sender@example.com")
	}
}

// BenchmarkSPFTestComplex benchmarks SPF evaluation with complex record
func BenchmarkSPFTestComplex(b *testing.B) {
	resolver := &MockResolver{
		TXTRecords: map[string][]string{
			"example.com":      {"v=spf1 ip4:192.0.2.0/24 a mx include:spf1.example.com include:spf2.example.com -all"},
			"spf1.example.com": {"v=spf1 ip4:198.51.100.0/24 a:mail.spf1.example.com -all"},
			"spf2.example.com": {"v=spf1 ip4:203.0.113.0/24 mx -all"},
		},
		HostRecords: map[string][]string{
			"example.com":          {"192.0.2.1"},
			"mail.spf1.example.com": {"198.51.100.1"},
		},
		MXRecords: map[string][]*net.MX{
			"example.com": {
				{Host: "mx1.example.com", Pref: 10},
			},
			"spf2.example.com": {
				{Host: "mx2.example.com", Pref: 10},
			},
		},
	}

	// Add host records for MX servers
	resolver.HostRecords["mx1.example.com"] = []string{"192.0.2.10"}
	resolver.HostRecords["mx2.example.com"] = []string{"203.0.113.10"}

	ctx := context.Background()
	config := &Config{
		MaxLookups:  MaxCount,
		DNSResolver: resolver,
		DNSTimeout:  10 * time.Second,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = SPFTestContext(ctx, config, "192.0.2.1", "sender@example.com")
	}
}

// BenchmarkSPFTestWithCache benchmarks SPF evaluation with caching enabled
func BenchmarkSPFTestWithCache(b *testing.B) {
	mockResolver := &MockResolver{
		TXTRecords: map[string][]string{
			"example.com": {"v=spf1 ip4:192.0.2.0/24 -all"},
		},
	}

	cachedResolver := NewCachedResolver(mockResolver, 5*time.Minute)

	ctx := context.Background()
	config := &Config{
		MaxLookups:  MaxCount,
		DNSResolver: cachedResolver,
		DNSTimeout:  10 * time.Second,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = SPFTestContext(ctx, config, "192.0.2.1", "sender@example.com")
	}
}

// BenchmarkNewMechanism benchmarks mechanism parsing
func BenchmarkNewMechanism(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewMechanism("ip4:192.0.2.0/24", "example.com")
	}
}

// BenchmarkMechanismEvaluate benchmarks mechanism evaluation
func BenchmarkMechanismEvaluate(b *testing.B) {
	m, err := NewMechanism("ip4:192.0.2.0/24", "example.com")
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = m.Evaluate("192.0.2.1", 0)
	}
}

// BenchmarkNetworkCIDR benchmarks CIDR network creation
func BenchmarkNetworkCIDR(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = networkCIDR("192.0.2.0", "24")
	}
}

// BenchmarkIPv6CIDR benchmarks IPv6 CIDR network creation
func BenchmarkIPv6CIDR(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = networkCIDR("2001:db8::", "32")
	}
}

// BenchmarkCacheGet benchmarks cache retrieval
func BenchmarkCacheGet(b *testing.B) {
	cache := NewDNSCache(5 * time.Minute)
	cache.set("test-key", []string{"value1", "value2"})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.get("test-key")
	}
}

// BenchmarkCacheSet benchmarks cache storage
func BenchmarkCacheSet(b *testing.B) {
	cache := NewDNSCache(5 * time.Minute)
	value := []string{"value1", "value2"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.set("test-key", value)
	}
}

// BenchmarkParallelMXLookups benchmarks parallel MX lookups
func BenchmarkParallelMXLookups(b *testing.B) {
	resolver := &MockResolver{
		TXTRecords: map[string][]string{
			"example.com": {"v=spf1 mx -all"},
		},
		MXRecords: map[string][]*net.MX{
			"example.com": {
				{Host: "mx1.example.com", Pref: 10},
				{Host: "mx2.example.com", Pref: 20},
				{Host: "mx3.example.com", Pref: 30},
				{Host: "mx4.example.com", Pref: 40},
				{Host: "mx5.example.com", Pref: 50},
			},
		},
		HostRecords: map[string][]string{
			"mx1.example.com": {"192.0.2.10"},
			"mx2.example.com": {"192.0.2.20"},
			"mx3.example.com": {"192.0.2.30"},
			"mx4.example.com": {"192.0.2.40"},
			"mx5.example.com": {"192.0.2.50"},
		},
	}

	ctx := context.Background()
	config := &Config{
		MaxLookups:  MaxCount,
		DNSResolver: resolver,
		DNSTimeout:  10 * time.Second,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = SPFTestContext(ctx, config, "192.0.2.30", "sender@example.com")
	}
}
