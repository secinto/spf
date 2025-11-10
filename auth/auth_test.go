package auth

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/asggo/spf"
	"github.com/asggo/spf/dkim"
	"github.com/asggo/spf/dmarc"
)

// MockResolver implements DNSResolver for testing
type MockResolver struct {
	SPFRecords   map[string][]string
	TXTRecords   map[string][]string
	HostRecords  map[string][]string
	MXRecords    map[string][]*net.MX
	AddrRecords  map[string][]string
	DMARCRecords map[string]string
}

func (m *MockResolver) LookupTXT(ctx context.Context, domain string) ([]string, error) {
	// Check for DMARC record
	if strings.HasPrefix(domain, "_dmarc.") {
		if record, ok := m.DMARCRecords[domain]; ok {
			return []string{record}, nil
		}
	}

	// Check for DKIM record
	if strings.Contains(domain, "._domainkey.") {
		if records, ok := m.TXTRecords[domain]; ok {
			return records, nil
		}
	}

	// Check for SPF record
	if records, ok := m.SPFRecords[domain]; ok {
		return records, nil
	}

	if records, ok := m.TXTRecords[domain]; ok {
		return records, nil
	}

	return nil, &net.DNSError{Err: "no such host", Name: domain, IsNotFound: true}
}

func (m *MockResolver) LookupHost(ctx context.Context, domain string) ([]string, error) {
	if records, ok := m.HostRecords[domain]; ok {
		return records, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: domain, IsNotFound: true}
}

func (m *MockResolver) LookupMX(ctx context.Context, domain string) ([]*net.MX, error) {
	if records, ok := m.MXRecords[domain]; ok {
		return records, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: domain, IsNotFound: true}
}

func (m *MockResolver) LookupAddr(ctx context.Context, ip string) ([]string, error) {
	if records, ok := m.AddrRecords[ip]; ok {
		return records, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: ip, IsNotFound: true}
}

// createDKIMSignature creates a valid DKIM signature for testing
func createDKIMSignature(privateKey *rsa.PrivateKey, selector, domain string, headers []dkim.Header, body []byte) string {
	// Compute body hash
	bodyCanon := dkim.CanonicalizeBody(body, dkim.CanonSimple)
	bodyHasher := sha256.New()
	bodyHasher.Write(bodyCanon)
	bodyHash := bodyHasher.Sum(nil)

	// Canonicalize headers
	signedHeaders := []string{"from", "to", "subject"}
	headerCanon := dkim.CanonicalizeHeaders(headers, dkim.CanonRelaxed, signedHeaders)

	// Create signature header template
	sigHeaderCanon := fmt.Sprintf("dkim-signature:v=1; a=rsa-sha256; b=; bh=%s; c=relaxed/simple; d=%s; h=from:to:subject; s=%s",
		base64.StdEncoding.EncodeToString(bodyHash), domain, selector)

	// Sign
	signData := append(headerCanon, []byte(sigHeaderCanon)...)
	hasher := sha256.New()
	hasher.Write(signData)
	hash := hasher.Sum(nil)

	signature, _ := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash)

	return fmt.Sprintf("v=1; a=rsa-sha256; b=%s; bh=%s; c=relaxed/simple; d=%s; h=from:to:subject; s=%s",
		base64.StdEncoding.EncodeToString(signature),
		base64.StdEncoding.EncodeToString(bodyHash),
		domain, selector)
}

func TestAuthenticateFullPass(t *testing.T) {
	// Generate RSA key for DKIM
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}
	publicKeyBase64 := base64.StdEncoding.EncodeToString(publicKeyBytes)

	// Prepare message
	body := []byte("This is a test message.\r\n")
	headers := []dkim.Header{
		{Name: "From", Value: "sender@example.com"},
		{Name: "To", Value: "recipient@test.com"},
		{Name: "Subject", Value: "Test Message"},
	}

	// Create DKIM signature
	dkimSig := createDKIMSignature(privateKey, "default", "example.com", headers, body)

	// Add DKIM signature to headers
	message := &EmailMessage{
		Headers: append([]dkim.Header{
			{Name: "DKIM-Signature", Value: dkimSig},
		}, headers...),
		Body:           body,
		EnvelopeSender: "sender@example.com",
		ClientIP:       "192.0.2.1",
	}

	// Setup mock resolver
	resolver := &MockResolver{
		SPFRecords: map[string][]string{
			"example.com": {"v=spf1 ip4:192.0.2.0/24 -all"},
		},
		TXTRecords: map[string][]string{
			"default._domainkey.example.com": {
				"v=DKIM1; k=rsa; p=" + publicKeyBase64,
			},
		},
		DMARCRecords: map[string]string{
			"_dmarc.example.com": "v=DMARC1; p=reject; aspf=r; adkim=r",
		},
	}

	// Authenticate
	ctx := context.Background()
	result, err := Authenticate(ctx, resolver, message)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}

	// Verify results
	if result.DMARC.Error != nil {
		t.Fatalf("DMARC error: %v", result.DMARC.Error)
	}

	if !result.Authenticated {
		t.Errorf("Expected authenticated=true, got false. Reason: %s", result.Reason)
	}

	if result.SPF.Result != spf.Pass {
		t.Errorf("Expected SPF pass, got %v", result.SPF.Result)
	}

	if len(result.DKIM) == 0 || !result.DKIM[0].Valid {
		t.Errorf("Expected valid DKIM signature")
	}

	if !result.DMARC.SPFAligned {
		t.Errorf("Expected SPF aligned, got false")
	}

	if !result.DMARC.DKIMAligned {
		t.Errorf("Expected DKIM aligned, got false")
	}

	if result.DMARC.Policy != dmarc.PolicyReject {
		t.Errorf("Expected DMARC policy=reject, got %v", result.DMARC.Policy)
	}

	// Check Authentication-Results header
	if !strings.Contains(result.AuthResultsHeader, "spf=pass") {
		t.Errorf("Auth results missing spf=pass: %s", result.AuthResultsHeader)
	}
	if !strings.Contains(result.AuthResultsHeader, "dkim=pass") {
		t.Errorf("Auth results missing dkim=pass: %s", result.AuthResultsHeader)
	}
	if !strings.Contains(result.AuthResultsHeader, "dmarc=pass") {
		t.Errorf("Auth results missing dmarc=pass: %s", result.AuthResultsHeader)
	}
}

func TestAuthenticateSPFFail(t *testing.T) {
	// Generate RSA key for DKIM
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}
	publicKeyBase64 := base64.StdEncoding.EncodeToString(publicKeyBytes)

	// Prepare message
	body := []byte("This is a test message.\r\n")
	headers := []dkim.Header{
		{Name: "From", Value: "sender@example.com"},
		{Name: "To", Value: "recipient@test.com"},
		{Name: "Subject", Value: "Test Message"},
	}

	// Create DKIM signature
	dkimSig := createDKIMSignature(privateKey, "default", "example.com", headers, body)

	message := &EmailMessage{
		Headers: append([]dkim.Header{
			{Name: "DKIM-Signature", Value: dkimSig},
		}, headers...),
		Body:           body,
		EnvelopeSender: "sender@example.com",
		ClientIP:       "198.51.100.1", // Different IP, will fail SPF
	}

	resolver := &MockResolver{
		SPFRecords: map[string][]string{
			"example.com": {"v=spf1 ip4:192.0.2.0/24 -all"},
		},
		TXTRecords: map[string][]string{
			"default._domainkey.example.com": {
				"v=DKIM1; k=rsa; p=" + publicKeyBase64,
			},
		},
		DMARCRecords: map[string]string{
			"_dmarc.example.com": "v=DMARC1; p=reject; aspf=r; adkim=r",
		},
	}

	ctx := context.Background()
	result, err := Authenticate(ctx, resolver, message)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}

	// SPF should fail
	if result.SPF.Result == spf.Pass {
		t.Errorf("Expected SPF fail, got pass")
	}

	// But DKIM should pass
	if len(result.DKIM) == 0 || !result.DKIM[0].Valid {
		t.Errorf("Expected valid DKIM signature")
	}

	// DMARC should still pass because DKIM aligned
	if !result.Authenticated {
		t.Errorf("Expected authenticated=true (DKIM aligned), got false. Reason: %s", result.Reason)
	}

	if !result.DMARC.DKIMAligned {
		t.Errorf("Expected DKIM aligned")
	}
}

func TestAuthenticateDKIMFail(t *testing.T) {
	message := &EmailMessage{
		Headers: []dkim.Header{
			{Name: "From", Value: "sender@example.com"},
			{Name: "To", Value: "recipient@test.com"},
			{Name: "Subject", Value: "Test Message"},
			// Invalid DKIM signature
			{Name: "DKIM-Signature", Value: "v=1; a=rsa-sha256; b=invalidsig; bh=invalidhash; c=relaxed/simple; d=example.com; h=from; s=default"},
		},
		Body:           []byte("This is a test message.\r\n"),
		EnvelopeSender: "sender@example.com",
		ClientIP:       "192.0.2.1",
	}

	resolver := &MockResolver{
		SPFRecords: map[string][]string{
			"example.com": {"v=spf1 ip4:192.0.2.0/24 -all"},
		},
		TXTRecords:   map[string][]string{},
		DMARCRecords: map[string]string{
			"_dmarc.example.com": "v=DMARC1; p=reject; aspf=r; adkim=r",
		},
	}

	ctx := context.Background()
	result, err := Authenticate(ctx, resolver, message)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}

	// SPF should pass
	if result.SPF.Result != spf.Pass {
		t.Errorf("Expected SPF pass, got %v", result.SPF.Result)
	}

	// DMARC should still pass because SPF aligned
	if !result.Authenticated {
		t.Errorf("Expected authenticated=true (SPF aligned), got false. Reason: %s", result.Reason)
	}

	if !result.DMARC.SPFAligned {
		t.Errorf("Expected SPF aligned")
	}
}

func TestAuthenticateBothFail(t *testing.T) {
	message := &EmailMessage{
		Headers: []dkim.Header{
			{Name: "From", Value: "sender@example.com"},
			{Name: "To", Value: "recipient@test.com"},
			{Name: "Subject", Value: "Test Message"},
		},
		Body:           []byte("This is a test message.\r\n"),
		EnvelopeSender: "sender@example.com",
		ClientIP:       "198.51.100.1", // Will fail SPF
	}

	resolver := &MockResolver{
		SPFRecords: map[string][]string{
			"example.com": {"v=spf1 ip4:192.0.2.0/24 -all"},
		},
		TXTRecords: map[string][]string{},
		DMARCRecords: map[string]string{
			"_dmarc.example.com": "v=DMARC1; p=reject; aspf=r; adkim=r",
		},
	}

	ctx := context.Background()
	result, err := Authenticate(ctx, resolver, message)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}

	// Both SPF and DKIM should fail
	if result.SPF.Result == spf.Pass {
		t.Errorf("Expected SPF fail, got pass")
	}

	// Should not be authenticated due to DMARC policy reject
	if result.Authenticated {
		t.Errorf("Expected authenticated=false, got true")
	}

	if result.DMARC.Disposition != dmarc.DispositionReject {
		t.Errorf("Expected disposition=reject, got %v", result.DMARC.Disposition)
	}
}

func TestAuthenticateNoDMARC(t *testing.T) {
	// Generate RSA key for DKIM
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}
	publicKeyBase64 := base64.StdEncoding.EncodeToString(publicKeyBytes)

	body := []byte("This is a test message.\r\n")
	headers := []dkim.Header{
		{Name: "From", Value: "sender@example.com"},
		{Name: "To", Value: "recipient@test.com"},
		{Name: "Subject", Value: "Test Message"},
	}

	dkimSig := createDKIMSignature(privateKey, "default", "example.com", headers, body)

	message := &EmailMessage{
		Headers: append([]dkim.Header{
			{Name: "DKIM-Signature", Value: dkimSig},
		}, headers...),
		Body:           body,
		EnvelopeSender: "sender@example.com",
		ClientIP:       "198.51.100.1", // Will fail SPF
	}

	resolver := &MockResolver{
		SPFRecords: map[string][]string{
			"example.com": {"v=spf1 ip4:192.0.2.0/24 -all"},
		},
		TXTRecords: map[string][]string{
			"default._domainkey.example.com": {
				"v=DKIM1; k=rsa; p=" + publicKeyBase64,
			},
		},
		DMARCRecords: map[string]string{},
	}

	ctx := context.Background()
	result, err := Authenticate(ctx, resolver, message)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}

	// Should pass based on DKIM even though SPF fails
	if !result.Authenticated {
		t.Errorf("Expected authenticated=true (DKIM pass, no DMARC), got false. Reason: %s", result.Reason)
	}

	if !result.DKIM[0].Valid {
		t.Errorf("Expected valid DKIM")
	}
}

func TestAuthenticateDMARCQuarantine(t *testing.T) {
	message := &EmailMessage{
		Headers: []dkim.Header{
			{Name: "From", Value: "sender@example.com"},
			{Name: "To", Value: "recipient@test.com"},
			{Name: "Subject", Value: "Test Message"},
		},
		Body:           []byte("This is a test message.\r\n"),
		EnvelopeSender: "sender@example.com",
		ClientIP:       "198.51.100.1",
	}

	resolver := &MockResolver{
		SPFRecords: map[string][]string{
			"example.com": {"v=spf1 ip4:192.0.2.0/24 -all"},
		},
		TXTRecords: map[string][]string{},
		DMARCRecords: map[string]string{
			"_dmarc.example.com": "v=DMARC1; p=quarantine; aspf=r; adkim=r",
		},
	}

	ctx := context.Background()
	result, err := Authenticate(ctx, resolver, message)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}

	if result.Authenticated {
		t.Errorf("Expected authenticated=false, got true")
	}

	if result.DMARC.Policy != dmarc.PolicyQuarantine {
		t.Errorf("Expected policy=quarantine, got %v", result.DMARC.Policy)
	}

	if result.DMARC.Disposition != dmarc.DispositionQuarantine {
		t.Errorf("Expected disposition=quarantine, got %v", result.DMARC.Disposition)
	}

	if !strings.Contains(result.Reason, "quarantine") {
		t.Errorf("Expected reason to mention quarantine, got: %s", result.Reason)
	}
}

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		email string
		want  string
	}{
		{"user@example.com", "example.com"},
		{"User Name <user@example.com>", "example.com"},
		{"user+tag@example.com", "example.com"},
		{"user@EXAMPLE.COM", "example.com"},
		{"<user@example.com>", "example.com"},
		{"invalid", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.email, func(t *testing.T) {
			got := extractDomain(tt.email)
			if got != tt.want {
				t.Errorf("extractDomain(%q) = %q, want %q", tt.email, got, tt.want)
			}
		})
	}
}

func TestAuthenticateED25519(t *testing.T) {
	// Generate ED25519 key for DKIM
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ED25519 key: %v", err)
	}
	publicKeyBase64 := base64.StdEncoding.EncodeToString(publicKey)

	// Prepare message
	body := []byte("This is a test message.\r\n")
	headers := []dkim.Header{
		{Name: "From", Value: "sender@example.com"},
		{Name: "To", Value: "recipient@test.com"},
		{Name: "Subject", Value: "Test Message"},
	}

	// Create ED25519 DKIM signature
	bodyCanon := dkim.CanonicalizeBody(body, dkim.CanonSimple)
	bodyHasher := sha256.New()
	bodyHasher.Write(bodyCanon)
	bodyHash := bodyHasher.Sum(nil)

	signedHeaders := []string{"from", "to", "subject"}
	headerCanon := dkim.CanonicalizeHeaders(headers, dkim.CanonRelaxed, signedHeaders)

	sigHeaderCanon := fmt.Sprintf("dkim-signature:v=1; a=ed25519-sha256; b=; bh=%s; c=relaxed/simple; d=example.com; h=from:to:subject; s=default",
		base64.StdEncoding.EncodeToString(bodyHash))

	signData := append(headerCanon, []byte(sigHeaderCanon)...)
	hash := sha256.Sum256(signData)
	signature := ed25519.Sign(privateKey, hash[:])

	dkimSig := fmt.Sprintf("v=1; a=ed25519-sha256; b=%s; bh=%s; c=relaxed/simple; d=example.com; h=from:to:subject; s=default",
		base64.StdEncoding.EncodeToString(signature),
		base64.StdEncoding.EncodeToString(bodyHash))

	message := &EmailMessage{
		Headers: append([]dkim.Header{
			{Name: "DKIM-Signature", Value: dkimSig},
		}, headers...),
		Body:           body,
		EnvelopeSender: "sender@example.com",
		ClientIP:       "192.0.2.1",
	}

	resolver := &MockResolver{
		SPFRecords: map[string][]string{
			"example.com": {"v=spf1 ip4:192.0.2.0/24 -all"},
		},
		TXTRecords: map[string][]string{
			"default._domainkey.example.com": {
				"v=DKIM1; k=ed25519; p=" + publicKeyBase64,
			},
		},
		DMARCRecords: map[string]string{
			"_dmarc.example.com": "v=DMARC1; p=reject; aspf=r; adkim=r",
		},
	}

	ctx := context.Background()
	result, err := Authenticate(ctx, resolver, message)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}

	if !result.Authenticated {
		t.Errorf("Expected authenticated=true, got false. Reason: %s", result.Reason)
	}

	if len(result.DKIM) == 0 || !result.DKIM[0].Valid {
		t.Errorf("Expected valid ED25519 DKIM signature")
	}
}
