package spf

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
)

func networkCIDR(ip, prefix string) (*net.IPNet, error) {
	if prefix == "" {
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			return nil, ErrInvalidIP
		}

		if parsedIP.To4() != nil {
			prefix = DefaultIPv4Prefix
		} else {
			prefix = DefaultIPv6Prefix
		}
	}

	cidrStr := fmt.Sprintf("%s/%s", ip, prefix)

	_, network, err := net.ParseCIDR(cidrStr)
	return network, err
}

func ipInNetworks(ip net.IP, networks []*net.IPNet) bool {
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

func buildNetworks(ips []string, prefix string) ([]*net.IPNet, error) {
	var networks []*net.IPNet
	var lastErr error

	for _, ip := range ips {
		network, err := networkCIDR(ip, prefix)
		if err == nil {
			networks = append(networks, network)
		} else {
			lastErr = err
		}
	}

	// Return networks even if some failed, but report last error
	return networks, lastErr
}

func aNetworks(ctx context.Context, resolver DNSResolver, m *Mechanism) ([]*net.IPNet, error) {
	ips, err := resolver.LookupHost(ctx, m.Domain)
	if err != nil {
		return nil, err
	}

	networks, _ := buildNetworks(ips, m.Prefix)
	return networks, nil
}

func mxNetworks(ctx context.Context, resolver DNSResolver, m *Mechanism) ([]*net.IPNet, error) {
	var networks []*net.IPNet

	mxs, err := resolver.LookupMX(ctx, m.Domain)
	if err != nil {
		return nil, err
	}

	// Parallelize MX host lookups for better performance
	type mxResult struct {
		networks []*net.IPNet
		err      error
	}

	results := make(chan mxResult, len(mxs))
	var wg sync.WaitGroup

	for _, mx := range mxs {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			ips, err := resolver.LookupHost(ctx, host)
			if err != nil {
				results <- mxResult{nil, err}
				return
			}
			nets, _ := buildNetworks(ips, m.Prefix)
			results <- mxResult{nets, nil}
		}(mx.Host)
	}

	// Close results channel when all goroutines complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	var lastErr error
	for result := range results {
		if result.err != nil {
			lastErr = result.err
		} else {
			networks = append(networks, result.networks...)
		}
	}

	// Return networks even if some MX lookups failed
	return networks, lastErr
}

func testPTR(ctx context.Context, resolver DNSResolver, m *Mechanism, ip string) (bool, error) {
	names, err := resolver.LookupAddr(ctx, ip)
	if err != nil {
		return false, err
	}

	for _, name := range names {
		if strings.HasSuffix(name, m.Domain) {
			return true, nil
		}
	}

	return false, nil
}
