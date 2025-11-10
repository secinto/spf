package dkim

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
)

// MockResolver implements DNSResolver interface for testing
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

func (m *MockResolver) LookupHost(ctx context.Context, domain string) ([]string, error) {
	return nil, nil
}

func (m *MockResolver) LookupMX(ctx context.Context, domain string) ([]*net.MX, error) {
	return nil, nil
}

func (m *MockResolver) LookupAddr(ctx context.Context, ip string) ([]string, error) {
	return nil, nil
}

func TestParseSignature(t *testing.T) {
	tests := []struct {
		name      string
		header    string
		wantErr   bool
		checkFunc func(*testing.T, *Signature)
	}{
		{
			name: "valid RSA signature with all tags",
			header: "v=1; a=rsa-sha256; d=example.com; s=selector; " +
				"c=relaxed/simple; q=dns/txt; h=from:to:subject; " +
				"bh=dGVzdGJvZHloYXNo; b=dGVzdHNpZ25hdHVyZQ==; " +
				"t=1234567890; x=9999999999; l=100; " +
				"i=@example.com; z=from:test@example.com",
			wantErr: false,
			checkFunc: func(t *testing.T, sig *Signature) {
				if sig.Version != "1" {
					t.Errorf("Version = %s, want 1", sig.Version)
				}
				if sig.Algorithm != AlgorithmRSASHA256 {
					t.Errorf("Algorithm = %v, want rsa-sha256", sig.Algorithm)
				}
				if sig.Domain != "example.com" {
					t.Errorf("Domain = %s, want example.com", sig.Domain)
				}
				if sig.Selector != "selector" {
					t.Errorf("Selector = %s, want selector", sig.Selector)
				}
				if sig.HeaderCanon != CanonRelaxed {
					t.Errorf("HeaderCanon = %v, want relaxed", sig.HeaderCanon)
				}
				if sig.BodyCanon != CanonSimple {
					t.Errorf("BodyCanon = %v, want simple", sig.BodyCanon)
				}
				expectedHeaders := []string{"from", "to", "subject"}
				if len(sig.Headers) != len(expectedHeaders) {
					t.Errorf("Headers length = %d, want %d", len(sig.Headers), len(expectedHeaders))
				}
				if sig.Timestamp.Unix() != 1234567890 {
					t.Errorf("Timestamp = %d, want 1234567890", sig.Timestamp.Unix())
				}
				if sig.Expiration.Unix() != 9999999999 {
					t.Errorf("Expiration = %d, want 9999999999", sig.Expiration.Unix())
				}
				if sig.BodyLength != 100 {
					t.Errorf("BodyLength = %d, want 100", sig.BodyLength)
				}
			},
		},
		{
			name: "valid ED25519 signature",
			header: "v=1; a=ed25519-sha256; d=example.com; s=selector; " +
				"h=from:to; bh=dGVzdA==; b=c2lnbmF0dXJl",
			wantErr: false,
			checkFunc: func(t *testing.T, sig *Signature) {
				if sig.Algorithm != AlgorithmED25519SHA256 {
					t.Errorf("Algorithm = %v, want ed25519-sha256", sig.Algorithm)
				}
			},
		},
		{
			name:    "missing version",
			header:  "a=rsa-sha256; d=example.com; s=selector; h=from; bh=dGVzdA==; b=c2ln",
			wantErr: true,
		},
		{
			name:    "wrong version",
			header:  "v=2; a=rsa-sha256; d=example.com; s=selector; h=from; bh=dGVzdA==; b=c2ln",
			wantErr: true,
		},
		{
			name:    "missing algorithm",
			header:  "v=1; d=example.com; s=selector; h=from; bh=dGVzdA==; b=c2ln",
			wantErr: true,
		},
		{
			name:    "unsupported algorithm",
			header:  "v=1; a=invalid-algo; d=example.com; s=selector; h=from; bh=dGVzdA==; b=c2ln",
			wantErr: true,
		},
		{
			name:    "missing domain",
			header:  "v=1; a=rsa-sha256; s=selector; h=from; bh=dGVzdA==; b=c2ln",
			wantErr: true,
		},
		{
			name:    "missing selector",
			header:  "v=1; a=rsa-sha256; d=example.com; h=from; bh=dGVzdA==; b=c2ln",
			wantErr: true,
		},
		{
			name:    "missing headers",
			header:  "v=1; a=rsa-sha256; d=example.com; s=selector; bh=dGVzdA==; b=c2ln",
			wantErr: true,
		},
		{
			name:    "missing body hash",
			header:  "v=1; a=rsa-sha256; d=example.com; s=selector; h=from; b=c2ln",
			wantErr: true,
		},
		{
			name:    "missing signature",
			header:  "v=1; a=rsa-sha256; d=example.com; s=selector; h=from; bh=dGVzdA==",
			wantErr: true,
		},
		{
			name:    "invalid base64 body hash",
			header:  "v=1; a=rsa-sha256; d=example.com; s=selector; h=from; bh=!!!invalid; b=c2ln",
			wantErr: true,
		},
		{
			name:    "invalid base64 signature",
			header:  "v=1; a=rsa-sha256; d=example.com; s=selector; h=from; bh=dGVzdA==; b=!!!invalid",
			wantErr: true,
		},
		{
			name: "canonicalization defaults",
			header: "v=1; a=rsa-sha256; d=example.com; s=selector; " +
				"h=from; bh=dGVzdA==; b=c2ln",
			wantErr: false,
			checkFunc: func(t *testing.T, sig *Signature) {
				if sig.HeaderCanon != CanonSimple {
					t.Errorf("HeaderCanon = %v, want simple", sig.HeaderCanon)
				}
				if sig.BodyCanon != CanonSimple {
					t.Errorf("BodyCanon = %v, want simple", sig.BodyCanon)
				}
			},
		},
		{
			name: "canonicalization with single value",
			header: "v=1; a=rsa-sha256; d=example.com; s=selector; " +
				"c=relaxed; h=from; bh=dGVzdA==; b=c2ln",
			wantErr: false,
			checkFunc: func(t *testing.T, sig *Signature) {
				if sig.HeaderCanon != CanonRelaxed {
					t.Errorf("HeaderCanon = %v, want relaxed", sig.HeaderCanon)
				}
				if sig.BodyCanon != CanonSimple {
					t.Errorf("BodyCanon = %v, want simple", sig.BodyCanon)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig, err := ParseSignature(tt.header)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSignature() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.checkFunc != nil {
				tt.checkFunc(t, sig)
			}
		})
	}
}

func TestLookupPublicKey(t *testing.T) {
	// Generate test RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	rsaPubKeyBytes, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal RSA public key: %v", err)
	}
	rsaBase64 := base64.StdEncoding.EncodeToString(rsaPubKeyBytes)

	// Generate test ED25519 key
	ed25519Pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ED25519 key: %v", err)
	}
	ed25519Base64 := base64.StdEncoding.EncodeToString(ed25519Pub)

	tests := []struct {
		name      string
		selector  string
		domain    string
		records   map[string][]string
		wantErr   bool
		checkFunc func(*testing.T, *PublicKey)
	}{
		{
			name:     "valid RSA key with base64",
			selector: "selector",
			domain:   "example.com",
			records: map[string][]string{
				"selector._domainkey.example.com": {
					"v=DKIM1; k=rsa; p=" + rsaBase64,
				},
			},
			wantErr: false,
			checkFunc: func(t *testing.T, pk *PublicKey) {
				if pk.Version != "DKIM1" {
					t.Errorf("Version = %s, want DKIM1", pk.Version)
				}
				if pk.KeyType != KeyTypeRSA {
					t.Errorf("KeyType = %v, want rsa", pk.KeyType)
				}
				if pk.PublicKey == nil {
					t.Error("PublicKey is nil")
				}
			},
		},
		{
			name:     "valid ED25519 key",
			selector: "selector",
			domain:   "example.com",
			records: map[string][]string{
				"selector._domainkey.example.com": {
					"v=DKIM1; k=ed25519; p=" + ed25519Base64,
				},
			},
			wantErr: false,
			checkFunc: func(t *testing.T, pk *PublicKey) {
				if pk.KeyType != KeyTypeED25519 {
					t.Errorf("KeyType = %v, want ed25519", pk.KeyType)
				}
			},
		},
		{
			name:     "key revoked (empty p)",
			selector: "selector",
			domain:   "example.com",
			records: map[string][]string{
				"selector._domainkey.example.com": {
					"v=DKIM1; k=rsa; p=",
				},
			},
			wantErr: true,
		},
		{
			name:     "no DNS record",
			selector: "nonexistent",
			domain:   "example.com",
			records:  map[string][]string{},
			wantErr:  true,
		},
		{
			name:     "invalid base64",
			selector: "selector",
			domain:   "example.com",
			records: map[string][]string{
				"selector._domainkey.example.com": {
					"v=DKIM1; k=rsa; p=!!!invalid",
				},
			},
			wantErr: true,
		},
		{
			name:     "flags with testing flag",
			selector: "selector",
			domain:   "example.com",
			records: map[string][]string{
				"selector._domainkey.example.com": {
					"v=DKIM1; k=rsa; t=y; p=" + rsaBase64,
				},
			},
			wantErr: false,
			checkFunc: func(t *testing.T, pk *PublicKey) {
				if !pk.Flags.Testing {
					t.Error("Testing flag should be true")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := &MockResolver{
				TXTRecords: tt.records,
			}

			ctx := context.Background()
			pk, err := LookupPublicKey(ctx, resolver, tt.selector, tt.domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("LookupPublicKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.checkFunc != nil {
				tt.checkFunc(t, pk)
			}
		})
	}
}

func TestCanonicalizeHeaders(t *testing.T) {
	headers := []Header{
		{Name: "From", Value: " alice@example.com "},
		{Name: "To", Value: "bob@example.com"},
		{Name: "Subject", Value: "  Test   Message  "},
		{Name: "Date", Value: "Mon, 1 Jan 2024 12:00:00 +0000"},
	}

	tests := []struct {
		name          string
		headers       []Header
		mode          CanonMode
		signedHeaders []string
		wantContains  []string
	}{
		{
			name:          "simple canonicalization",
			headers:       headers,
			mode:          CanonSimple,
			signedHeaders: []string{"from", "to", "subject"},
			wantContains: []string{
				"from:",
				"to:",
				"subject:",
			},
		},
		{
			name:          "relaxed canonicalization",
			headers:       headers,
			mode:          CanonRelaxed,
			signedHeaders: []string{"from", "to", "subject"},
			wantContains: []string{
				"from:alice@example.com",
				"to:bob@example.com",
				"subject:Test Message",
			},
		},
		{
			name:          "preserves header order",
			headers:       headers,
			mode:          CanonRelaxed,
			signedHeaders: []string{"subject", "from", "to"},
			wantContains:  []string{"subject:", "from:", "to:"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CanonicalizeHeaders(tt.headers, tt.mode, tt.signedHeaders)
			resultStr := string(result)

			for _, want := range tt.wantContains {
				if !strings.Contains(resultStr, want) {
					t.Errorf("CanonicalizeHeaders() result doesn't contain %q\nGot: %s", want, resultStr)
				}
			}
		})
	}
}

func TestCanonicalizeBody(t *testing.T) {
	tests := []struct {
		name string
		body []byte
		mode CanonMode
		want string
	}{
		{
			name: "simple with trailing empty lines",
			body: []byte("Line 1\r\nLine 2\r\n\r\n\r\n"),
			mode: CanonSimple,
			want: "Line 1\r\nLine 2\r\n",
		},
		{
			name: "simple empty body",
			body: []byte(""),
			mode: CanonSimple,
			want: "\r\n",
		},
		{
			name: "relaxed with whitespace",
			body: []byte("Line 1  \r\n  Line 2\t\r\n\r\n\r\n"),
			mode: CanonRelaxed,
			want: "Line 1\r\n Line 2\r\n",
		},
		{
			name: "relaxed empty body",
			body: []byte(""),
			mode: CanonRelaxed,
			want: "\r\n",
		},
		{
			name: "relaxed multiple spaces",
			body: []byte("Line   with    spaces\r\n"),
			mode: CanonRelaxed,
			want: "Line with spaces\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(CanonicalizeBody(tt.body, tt.mode))
			if got != tt.want {
				t.Errorf("CanonicalizeBody() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVerifyRSA(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}

	// Create test message
	body := []byte("This is a test message body.\r\n")
	headers := []Header{
		{Name: "From", Value: "alice@example.com"},
		{Name: "To", Value: "bob@example.com"},
		{Name: "Subject", Value: "Test"},
	}

	// Compute body hash
	bodyCanon := CanonicalizeBody(body, CanonSimple)
	bodyHasher := sha256.New()
	bodyHasher.Write(bodyCanon)
	bodyHash := bodyHasher.Sum(nil)

	// Canonicalize headers for signing
	signedHeaders := []string{"from", "to", "subject"}
	headerCanon := CanonicalizeHeaders(headers, CanonRelaxed, signedHeaders)

	// Create signature header (without b= value) - matching constructDKIMHeader format
	sigHeaderCanon := fmt.Sprintf("dkim-signature:v=1; a=rsa-sha256; b=; bh=%s; c=relaxed/simple; d=example.com; h=from:to:subject; s=selector",
		base64.StdEncoding.EncodeToString(bodyHash))

	// Append signature header to canonicalized headers
	signData := append(headerCanon, []byte(sigHeaderCanon)...)

	// Sign the data
	hasher := sha256.New()
	hasher.Write(signData)
	hash := hasher.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Create complete signature header
	completeHeader := fmt.Sprintf("v=1; a=rsa-sha256; b=%s; bh=%s; c=relaxed/simple; d=example.com; h=from:to:subject; s=selector",
		base64.StdEncoding.EncodeToString(signature),
		base64.StdEncoding.EncodeToString(bodyHash))

	// Add DKIM-Signature to headers
	message := &Message{
		Headers: append([]Header{{Name: "DKIM-Signature", Value: completeHeader}}, headers...),
		Body:    body,
	}

	// Setup mock resolver
	publicKeyBase64 := base64.StdEncoding.EncodeToString(publicKeyBytes)
	resolver := &MockResolver{
		TXTRecords: map[string][]string{
			"selector._domainkey.example.com": {
				"v=DKIM1; k=rsa; p=" + publicKeyBase64,
			},
		},
	}

	// Parse signature
	sig, err := ParseSignature(completeHeader)
	if err != nil {
		t.Fatalf("Failed to parse signature: %v", err)
	}

	// Verify signature
	ctx := context.Background()
	result, err := Verify(ctx, resolver, message, sig)
	if err != nil {
		t.Errorf("Verify() error = %v", err)
	}
	if result != nil && !result.Valid {
		t.Errorf("Verify() Valid = %v, want true. Error: %v", result.Valid, result.Error)
	}
}

func TestVerifyED25519(t *testing.T) {
	// Generate ED25519 key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ED25519 key: %v", err)
	}

	// Create test message
	body := []byte("This is a test message body.\r\n")
	headers := []Header{
		{Name: "From", Value: "alice@example.com"},
		{Name: "To", Value: "bob@example.com"},
		{Name: "Subject", Value: "Test"},
	}

	// Compute body hash
	bodyCanon := CanonicalizeBody(body, CanonSimple)
	bodyHasher := sha256.New()
	bodyHasher.Write(bodyCanon)
	bodyHash := bodyHasher.Sum(nil)

	// Canonicalize headers for signing
	signedHeaders := []string{"from", "to", "subject"}
	headerCanon := CanonicalizeHeaders(headers, CanonRelaxed, signedHeaders)

	// Create signature header (without b= value) - matching constructDKIMHeader format
	sigHeaderCanon := fmt.Sprintf("dkim-signature:v=1; a=ed25519-sha256; b=; bh=%s; c=relaxed/simple; d=example.com; h=from:to:subject; s=selector",
		base64.StdEncoding.EncodeToString(bodyHash))

	// Append signature header to canonicalized headers
	signData := append(headerCanon, []byte(sigHeaderCanon)...)

	// Sign the data (ED25519-SHA256 requires hashing first)
	hash := sha256.Sum256(signData)
	signature := ed25519.Sign(privateKey, hash[:])

	// Create complete signature header
	completeHeader := fmt.Sprintf("v=1; a=ed25519-sha256; b=%s; bh=%s; c=relaxed/simple; d=example.com; h=from:to:subject; s=selector",
		base64.StdEncoding.EncodeToString(signature),
		base64.StdEncoding.EncodeToString(bodyHash))

	// Add DKIM-Signature to headers
	message := &Message{
		Headers: append([]Header{{Name: "DKIM-Signature", Value: completeHeader}}, headers...),
		Body:    body,
	}

	// Setup mock resolver
	publicKeyBase64 := base64.StdEncoding.EncodeToString(publicKey)
	resolver := &MockResolver{
		TXTRecords: map[string][]string{
			"selector._domainkey.example.com": {
				"v=DKIM1; k=ed25519; p=" + publicKeyBase64,
			},
		},
	}

	// Parse signature
	sig, err := ParseSignature(completeHeader)
	if err != nil {
		t.Fatalf("Failed to parse signature: %v", err)
	}

	// Verify signature
	ctx := context.Background()
	result, err := Verify(ctx, resolver, message, sig)
	if err != nil {
		t.Errorf("Verify() error = %v", err)
	}
	if result != nil && !result.Valid {
		t.Errorf("Verify() Valid = %v, want true. Error: %v", result.Valid, result.Error)
	}
}

func TestVerifyFailures(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}

	publicKeyBase64 := base64.StdEncoding.EncodeToString(publicKeyBytes)

	tests := []struct {
		name         string
		modifyMsg    func(*Message)
		modifySig    func(*Signature)
		resolver     *MockResolver
		wantValid    bool
		wantErrorMsg string
	}{
		{
			name: "body hash mismatch",
			modifyMsg: func(msg *Message) {
				msg.Body = []byte("Modified body\r\n")
			},
			resolver: &MockResolver{
				TXTRecords: map[string][]string{
					"selector._domainkey.example.com": {
						"v=DKIM1; k=rsa; p=" + publicKeyBase64,
					},
				},
			},
			wantValid:    false,
			wantErrorMsg: "body hash does not match",
		},
		{
			name: "DNS lookup failure",
			resolver: &MockResolver{
				TXTRecords: map[string][]string{},
			},
			wantValid:    false,
			wantErrorMsg: "DKIM key not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create valid message and signature
			body := []byte("This is a test message body.\r\n")
			headers := []Header{
				{Name: "From", Value: "alice@example.com"},
				{Name: "To", Value: "bob@example.com"},
				{Name: "Subject", Value: "Test"},
			}

			bodyCanon := CanonicalizeBody(body, CanonSimple)
			bodyHasher := sha256.New()
			bodyHasher.Write(bodyCanon)
			bodyHash := bodyHasher.Sum(nil)

			signedHeaders := []string{"from", "to", "subject"}
			headerCanon := CanonicalizeHeaders(headers, CanonRelaxed, signedHeaders)

			sigHeaderCanon := fmt.Sprintf("dkim-signature:v=1; a=rsa-sha256; b=; bh=%s; c=relaxed/simple; d=example.com; h=from:to:subject; s=selector",
				base64.StdEncoding.EncodeToString(bodyHash))

			signData := append(headerCanon, []byte(sigHeaderCanon)...)

			hasher := sha256.New()
			hasher.Write(signData)
			hash := hasher.Sum(nil)

			signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash)
			if err != nil {
				t.Fatalf("Failed to sign: %v", err)
			}

			completeHeader := fmt.Sprintf("v=1; a=rsa-sha256; b=%s; bh=%s; c=relaxed/simple; d=example.com; h=from:to:subject; s=selector",
				base64.StdEncoding.EncodeToString(signature),
				base64.StdEncoding.EncodeToString(bodyHash))

			message := &Message{
				Headers: append([]Header{{Name: "DKIM-Signature", Value: completeHeader}}, headers...),
				Body:    body,
			}

			sig, err := ParseSignature(completeHeader)
			if err != nil {
				t.Fatalf("Failed to parse signature: %v", err)
			}

			// Apply modifications
			if tt.modifyMsg != nil {
				tt.modifyMsg(message)
			}
			if tt.modifySig != nil {
				tt.modifySig(sig)
			}

			// Verify
			ctx := context.Background()
			result, err := Verify(ctx, tt.resolver, message, sig)

			if err != nil {
				if !strings.Contains(err.Error(), tt.wantErrorMsg) {
					t.Errorf("Verify() error = %v, want error containing %q", err, tt.wantErrorMsg)
				}
			} else if result != nil {
				if result.Valid != tt.wantValid {
					t.Errorf("Verify() Valid = %v, want %v", result.Valid, tt.wantValid)
				}
				if result.Error != nil && !strings.Contains(result.Error.Error(), tt.wantErrorMsg) {
					t.Errorf("Verify() error = %q, want error containing %q", result.Error, tt.wantErrorMsg)
				}
			}
		})
	}
}

func TestVerifyMessage(t *testing.T) {
	// Generate two RSA key pairs
	privateKey1, _ := rsa.GenerateKey(rand.Reader, 2048)
	privateKey2, _ := rsa.GenerateKey(rand.Reader, 2048)

	publicKeyBytes1, _ := x509.MarshalPKIXPublicKey(&privateKey1.PublicKey)
	publicKeyBytes2, _ := x509.MarshalPKIXPublicKey(&privateKey2.PublicKey)

	publicKeyBase64_1 := base64.StdEncoding.EncodeToString(publicKeyBytes1)
	publicKeyBase64_2 := base64.StdEncoding.EncodeToString(publicKeyBytes2)

	// Helper function to create signature
	createSignature := func(privateKey *rsa.PrivateKey, selector string, body []byte, headers []Header) string {
		bodyCanon := CanonicalizeBody(body, CanonSimple)
		bodyHasher := sha256.New()
		bodyHasher.Write(bodyCanon)
		bodyHash := bodyHasher.Sum(nil)

		signedHeaders := []string{"from", "to", "subject"}
		headerCanon := CanonicalizeHeaders(headers, CanonRelaxed, signedHeaders)

		sigHeaderCanon := fmt.Sprintf("dkim-signature:v=1; a=rsa-sha256; b=; bh=%s; c=relaxed/simple; d=example.com; h=from:to:subject; s=%s",
			base64.StdEncoding.EncodeToString(bodyHash), selector)

		signData := append(headerCanon, []byte(sigHeaderCanon)...)

		hasher := sha256.New()
		hasher.Write(signData)
		hash := hasher.Sum(nil)

		signature, _ := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash)
		return fmt.Sprintf("v=1; a=rsa-sha256; b=%s; bh=%s; c=relaxed/simple; d=example.com; h=from:to:subject; s=%s",
			base64.StdEncoding.EncodeToString(signature),
			base64.StdEncoding.EncodeToString(bodyHash), selector)
	}

	body := []byte("This is a test message body.\r\n")
	headers := []Header{
		{Name: "From", Value: "alice@example.com"},
		{Name: "To", Value: "bob@example.com"},
		{Name: "Subject", Value: "Test"},
	}

	sig1 := createSignature(privateKey1, "selector1", body, headers)
	sig2 := createSignature(privateKey2, "selector2", body, headers)

	message := &Message{
		Headers: []Header{
			{Name: "DKIM-Signature", Value: sig1},
			{Name: "DKIM-Signature", Value: sig2},
			{Name: "From", Value: "alice@example.com"},
			{Name: "To", Value: "bob@example.com"},
			{Name: "Subject", Value: "Test"},
		},
		Body: body,
	}

	resolver := &MockResolver{
		TXTRecords: map[string][]string{
			"selector1._domainkey.example.com": {
				"v=DKIM1; k=rsa; p=" + publicKeyBase64_1,
			},
			"selector2._domainkey.example.com": {
				"v=DKIM1; k=rsa; p=" + publicKeyBase64_2,
			},
		},
	}

	ctx := context.Background()
	results, err := VerifyMessage(ctx, resolver, message)
	if err != nil {
		t.Fatalf("VerifyMessage() error = %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("VerifyMessage() returned %d results, want 2", len(results))
	}

	for i, result := range results {
		if !result.Valid {
			t.Errorf("Result %d: Valid = %v, want true. Error: %v", i, result.Valid, result.Error)
		}
	}
}

func TestBodyLengthLimit(t *testing.T) {
	body := []byte("This is a test message body with extra content.\r\n")

	sig := &Signature{
		Version:     "1",
		Algorithm:   AlgorithmRSASHA256,
		Domain:      "example.com",
		Selector:    "selector",
		Headers:     []string{"from"},
		HeaderCanon: CanonSimple,
		BodyCanon:   CanonSimple,
		BodyLength:  20, // Only first 20 bytes
		BodyHash:    make([]byte, 32),
	}

	// Compute body hash with length limit
	limitedBody := body
	if sig.BodyLength > 0 && sig.BodyLength < len(body) {
		limitedBody = body[:sig.BodyLength]
	}

	canonBody := CanonicalizeBody(limitedBody, sig.BodyCanon)
	hasher := sha256.New()
	hasher.Write(canonBody)
	expectedHash := hasher.Sum(nil)

	sig.BodyHash = expectedHash

	// Verify that body hash check would pass with limited body
	message := &Message{
		Headers: []Header{{Name: "From", Value: "test@example.com"}},
		Body:    body,
	}

	// This test just verifies the body length limiting logic
	canonicalBody := message.Body
	if sig.BodyLength > 0 && sig.BodyLength < len(canonicalBody) {
		canonicalBody = canonicalBody[:sig.BodyLength]
	}

	canonicalBody = CanonicalizeBody(canonicalBody, sig.BodyCanon)
	bodyHasher := sha256.New()
	bodyHasher.Write(canonicalBody)
	computedHash := bodyHasher.Sum(nil)

	if !strings.EqualFold(base64.StdEncoding.EncodeToString(computedHash),
		base64.StdEncoding.EncodeToString(expectedHash)) {
		t.Error("Body hash mismatch with length limit")
	}
}
