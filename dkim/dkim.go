// Package dkim implements RFC 6376 (DomainKeys Identified Mail) for verifying
// DKIM signatures on email messages.
//
// DKIM provides a method for validating domain-level authentication of email
// messages using cryptographic signatures. It allows senders to sign their
// messages and receivers to verify those signatures.
//
// Example usage:
//
//	ctx := context.Background()
//	resolver := spf.NewDefaultResolver()
//
//	// Parse DKIM signature from header
//	sig, err := dkim.ParseSignature(dkimHeader)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Verify signature
//	result, err := dkim.Verify(ctx, resolver, message, sig)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	if result.Valid {
//	    // Signature is valid
//	}
package dkim

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Algorithm represents a DKIM signing algorithm
type Algorithm string

const (
	// AlgorithmRSASHA1 is deprecated and should not be used
	AlgorithmRSASHA1 Algorithm = "rsa-sha1"
	// AlgorithmRSASHA256 is the recommended algorithm
	AlgorithmRSASHA256 Algorithm = "rsa-sha256"
	// AlgorithmED25519SHA256 is an optional modern algorithm
	AlgorithmED25519SHA256 Algorithm = "ed25519-sha256"
)

// CanonMode represents canonicalization mode
type CanonMode string

const (
	// CanonSimple preserves the message structure
	CanonSimple CanonMode = "simple"
	// CanonRelaxed allows whitespace modifications
	CanonRelaxed CanonMode = "relaxed"
)

// KeyType represents the public key type
type KeyType string

const (
	// KeyTypeRSA is RSA public key
	KeyTypeRSA KeyType = "rsa"
	// KeyTypeED25519 is ED25519 public key
	KeyTypeED25519 KeyType = "ed25519"
)

// Canonicalization holds header and body canonicalization modes
type Canonicalization struct {
	Header CanonMode
	Body   CanonMode
}

// Signature represents a parsed DKIM-Signature header
type Signature struct {
	// Required tags
	Version   string      // v=1
	Algorithm Algorithm   // a=rsa-sha256
	Signature []byte      // b=base64...
	BodyHash  []byte      // bh=base64...
	Domain    string      // d=example.com
	Selector  string      // s=default
	Headers   []string    // h=from:to:subject:date

	// Canonicalization
	HeaderCanon CanonMode // c=relaxed/simple (header)
	BodyCanon   CanonMode // c=relaxed/simple (body)

	// Optional tags
	BodyLength   int       // l=1234 (dangerous, avoid using)
	QueryMethod  string    // q=dns/txt (default)
	Identity     string    // i=user@example.com
	Timestamp    time.Time // t=1234567890
	Expiration   time.Time // x=1234567890
	CopiedHeaders map[string]string // z=header:value|header:value

	// Metadata
	Raw string // Original header value
}

// PublicKey represents a DKIM public key from DNS
type PublicKey struct {
	Version   string      // v=DKIM1
	KeyType   KeyType     // k=rsa or k=ed25519
	PublicKey interface{} // *rsa.PublicKey or ed25519.PublicKey
	Services  []string    // s=email:* (default: *)
	Flags     Flags       // t=y:s
	Notes     string      // n=notes

	// Metadata
	Raw      string
	Domain   string
	Selector string
}

// Flags represents DKIM key flags
type Flags struct {
	Testing      bool // t=y (testing mode)
	StrictDomain bool // t=s (subdomain matching disallowed)
}

// Result represents DKIM verification result
type Result struct {
	Valid         bool
	Domain        string
	Selector      string
	Algorithm     Algorithm
	Error         error
	SignatureTime time.Time
	HeadersOK     bool
	BodyOK        bool
}

// Header represents an email header
type Header struct {
	Name  string
	Value string
}

// Message represents an email message for DKIM operations
type Message struct {
	Headers []Header
	Body    []byte
}

// DNSResolver interface for DNS lookups
type DNSResolver interface {
	LookupTXT(ctx context.Context, domain string) ([]string, error)
}

// Errors
var (
	ErrNoSignature          = errors.New("no DKIM signature found")
	ErrInvalidVersion       = errors.New("invalid DKIM version")
	ErrInvalidAlgorithm     = errors.New("invalid or unsupported algorithm")
	ErrInvalidSignature     = errors.New("invalid signature format")
	ErrInvalidBodyHash      = errors.New("invalid body hash format")
	ErrMissingRequiredTag   = errors.New("missing required DKIM tag")
	ErrInvalidTimestamp     = errors.New("invalid timestamp")
	ErrInvalidExpiration    = errors.New("invalid expiration")
	ErrSignatureExpired     = errors.New("signature has expired")
	ErrInvalidBodyLength    = errors.New("invalid body length")
	ErrInvalidCanonicalization = errors.New("invalid canonicalization mode")
	ErrKeyNotFound          = errors.New("DKIM key not found in DNS")
	ErrInvalidKeyVersion    = errors.New("invalid key version")
	ErrUnsupportedKeyType   = errors.New("unsupported key type")
	ErrKeyRevoked           = errors.New("key has been revoked")
	ErrMissingPublicKey     = errors.New("missing public key in DNS record")
	ErrInvalidKeyType       = errors.New("invalid key type")
	ErrInvalidKeySize       = errors.New("invalid key size")
	ErrBodyHashMismatch     = errors.New("body hash does not match")
	ErrHeadersMismatch      = errors.New("headers signature does not match")
)

// ParseSignature parses a DKIM-Signature header value
func ParseSignature(header string) (*Signature, error) {
	sig := &Signature{
		Raw:         header,
		HeaderCanon: CanonSimple, // default
		BodyCanon:   CanonSimple, // default
		QueryMethod: "dns/txt",   // default
	}

	// Remove DKIM-Signature: prefix if present
	header = strings.TrimPrefix(header, "DKIM-Signature:")
	header = strings.TrimSpace(header)

	// Parse tag=value pairs
	tags := parseTagValueList(header)

	for tag, value := range tags {
		switch tag {
		case "v":
			if value != "1" {
				return nil, ErrInvalidVersion
			}
			sig.Version = value

		case "a":
			algo, err := parseAlgorithm(value)
			if err != nil {
				return nil, err
			}
			sig.Algorithm = algo

		case "b":
			// Signature may contain whitespace for folding
			value = strings.ReplaceAll(value, " ", "")
			value = strings.ReplaceAll(value, "\t", "")
			b, err := base64.StdEncoding.DecodeString(value)
			if err != nil {
				return nil, ErrInvalidSignature
			}
			sig.Signature = b

		case "bh":
			value = strings.ReplaceAll(value, " ", "")
			value = strings.ReplaceAll(value, "\t", "")
			bh, err := base64.StdEncoding.DecodeString(value)
			if err != nil {
				return nil, ErrInvalidBodyHash
			}
			sig.BodyHash = bh

		case "c":
			headerCanon, bodyCanon, err := parseCanonicalization(value)
			if err != nil {
				return nil, err
			}
			sig.HeaderCanon = headerCanon
			sig.BodyCanon = bodyCanon

		case "d":
			sig.Domain = value

		case "s":
			sig.Selector = value

		case "h":
			sig.Headers = strings.Split(value, ":")

		case "l":
			length, err := strconv.Atoi(value)
			if err != nil || length < 0 {
				return nil, ErrInvalidBodyLength
			}
			sig.BodyLength = length

		case "t":
			timestamp, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return nil, ErrInvalidTimestamp
			}
			sig.Timestamp = time.Unix(timestamp, 0)

		case "x":
			expiration, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return nil, ErrInvalidExpiration
			}
			sig.Expiration = time.Unix(expiration, 0)

		case "i":
			sig.Identity = value

		case "q":
			sig.QueryMethod = value

		case "z":
			sig.CopiedHeaders = parseCopiedHeaders(value)
		}
	}

	// Validate required tags
	if sig.Version == "" || sig.Algorithm == "" || sig.Domain == "" ||
		sig.Selector == "" || len(sig.Headers) == 0 ||
		len(sig.Signature) == 0 || len(sig.BodyHash) == 0 {
		return nil, ErrMissingRequiredTag
	}

	// Validate expiration
	if !sig.Expiration.IsZero() && time.Now().After(sig.Expiration) {
		return nil, ErrSignatureExpired
	}

	return sig, nil
}

// parseTagValueList parses DKIM tag=value pairs
func parseTagValueList(input string) map[string]string {
	tags := make(map[string]string)

	// Remove folding whitespace (FWS)
	input = strings.ReplaceAll(input, "\r\n", "")
	input = strings.ReplaceAll(input, "\n", "")

	// Split by semicolon
	pairs := strings.Split(input, ";")

	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 {
			continue
		}

		tag := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		tags[tag] = value
	}

	return tags
}

// parseAlgorithm parses an algorithm value
func parseAlgorithm(value string) (Algorithm, error) {
	switch value {
	case "rsa-sha1":
		return AlgorithmRSASHA1, nil
	case "rsa-sha256":
		return AlgorithmRSASHA256, nil
	case "ed25519-sha256":
		return AlgorithmED25519SHA256, nil
	default:
		return "", ErrInvalidAlgorithm
	}
}

// parseCanonicalization parses canonicalization value
func parseCanonicalization(value string) (CanonMode, CanonMode, error) {
	parts := strings.Split(value, "/")

	var headerCanon, bodyCanon CanonMode

	// Parse header canonicalization
	switch parts[0] {
	case "simple":
		headerCanon = CanonSimple
	case "relaxed":
		headerCanon = CanonRelaxed
	default:
		return "", "", ErrInvalidCanonicalization
	}

	// Parse body canonicalization (defaults to simple)
	if len(parts) > 1 {
		switch parts[1] {
		case "simple":
			bodyCanon = CanonSimple
		case "relaxed":
			bodyCanon = CanonRelaxed
		default:
			return "", "", ErrInvalidCanonicalization
		}
	} else {
		bodyCanon = CanonSimple
	}

	return headerCanon, bodyCanon, nil
}

// parseCopiedHeaders parses the z= tag (copied headers)
func parseCopiedHeaders(value string) map[string]string {
	headers := make(map[string]string)

	// Split by pipe character
	pairs := strings.Split(value, "|")

	for _, pair := range pairs {
		parts := strings.SplitN(pair, ":", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	return headers
}

// LookupPublicKey retrieves DKIM public key from DNS
func LookupPublicKey(ctx context.Context, resolver DNSResolver, selector, domain string) (*PublicKey, error) {
	// Construct DNS query: selector._domainkey.domain
	dkimDomain := fmt.Sprintf("%s._domainkey.%s", selector, domain)

	records, err := resolver.LookupTXT(ctx, dkimDomain)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			return nil, ErrKeyNotFound
		}
		return nil, err
	}

	// Concatenate multi-string TXT record
	var record string
	for _, r := range records {
		record += r
	}

	if record == "" {
		return nil, ErrKeyNotFound
	}

	return ParsePublicKey(record, selector, domain)
}

// ParsePublicKey parses a DKIM public key TXT record
func ParsePublicKey(record, selector, domain string) (*PublicKey, error) {
	key := &PublicKey{
		Raw:      record,
		Selector: selector,
		Domain:   domain,
		KeyType:  KeyTypeRSA, // default
		Services: []string{"*"}, // default: all services
	}

	tags := parseTagValueList(record)

	for tag, value := range tags {
		switch tag {
		case "v":
			if value != "DKIM1" {
				return nil, ErrInvalidKeyVersion
			}
			key.Version = value

		case "k":
			switch value {
			case "rsa":
				key.KeyType = KeyTypeRSA
			case "ed25519":
				key.KeyType = KeyTypeED25519
			default:
				return nil, ErrUnsupportedKeyType
			}

		case "p":
			if value == "" {
				// Revoked key
				return nil, ErrKeyRevoked
			}

			// Remove whitespace
			value = strings.ReplaceAll(value, " ", "")
			value = strings.ReplaceAll(value, "\t", "")

			pubKey, err := parsePublicKeyData(value, key.KeyType)
			if err != nil {
				return nil, err
			}
			key.PublicKey = pubKey

		case "s":
			if value != "*" {
				key.Services = strings.Split(value, ":")
			}

		case "t":
			flags := strings.Split(value, ":")
			for _, flag := range flags {
				switch flag {
				case "y":
					key.Flags.Testing = true
				case "s":
					key.Flags.StrictDomain = true
				}
			}

		case "n":
			key.Notes = value
		}
	}

	if key.PublicKey == nil {
		return nil, ErrMissingPublicKey
	}

	return key, nil
}

// parsePublicKeyData parses base64-encoded public key
func parsePublicKeyData(data string, keyType KeyType) (interface{}, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}

	switch keyType {
	case KeyTypeRSA:
		pubKey, err := x509.ParsePKIXPublicKey(keyBytes)
		if err != nil {
			return nil, err
		}

		rsaKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return nil, ErrInvalidKeyType
		}

		return rsaKey, nil

	case KeyTypeED25519:
		if len(keyBytes) != ed25519.PublicKeySize {
			return nil, ErrInvalidKeySize
		}
		return ed25519.PublicKey(keyBytes), nil

	default:
		return nil, ErrUnsupportedKeyType
	}
}

// CanonicalizeHeaders applies header canonicalization
func CanonicalizeHeaders(headers []Header, mode CanonMode, signedHeaders []string) []byte {
	var buf bytes.Buffer

	// Build map of headers
	headerMap := make(map[string][]string)
	for _, h := range headers {
		name := strings.ToLower(h.Name)
		headerMap[name] = append(headerMap[name], h.Value)
	}

	// Process headers in order specified by h= tag
	for _, name := range signedHeaders {
		name = strings.ToLower(name)
		values, exists := headerMap[name]
		if !exists || len(values) == 0 {
			continue
		}

		// Use most recent occurrence (last in list)
		value := values[len(values)-1]

		if mode == CanonSimple {
			buf.WriteString(name)
			buf.WriteString(": ")
			buf.WriteString(value)
			buf.WriteString("\r\n")
		} else {
			// Relaxed canonicalization
			buf.WriteString(canonicalizeHeaderName(name))
			buf.WriteString(":")
			buf.WriteString(canonicalizeHeaderValue(value))
			buf.WriteString("\r\n")
		}
	}

	// Remove trailing CRLF
	result := buf.Bytes()
	if len(result) >= 2 && result[len(result)-2] == '\r' && result[len(result)-1] == '\n' {
		result = result[:len(result)-2]
	}

	return result
}

func canonicalizeHeaderName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func canonicalizeHeaderValue(value string) string {
	// Convert all whitespace sequences to single space
	// Remove leading/trailing whitespace
	value = strings.TrimSpace(value)
	re := regexp.MustCompile(`\s+`)
	value = re.ReplaceAllString(value, " ")
	return value
}

// CanonicalizeBody applies body canonicalization
func CanonicalizeBody(body []byte, mode CanonMode) []byte {
	if mode == CanonSimple {
		return canonicalizeBodySimple(body)
	}
	return canonicalizeBodyRelaxed(body)
}

func canonicalizeBodySimple(body []byte) []byte {
	// Ignore all empty lines at the end of the message body
	// If body is completely empty, use single CRLF

	// Convert to CRLF line endings
	body = bytes.ReplaceAll(body, []byte("\r\n"), []byte("\n"))
	body = bytes.ReplaceAll(body, []byte("\n"), []byte("\r\n"))

	// Remove trailing empty lines
	for bytes.HasSuffix(body, []byte("\r\n\r\n")) {
		body = body[:len(body)-2]
	}

	// Ensure ends with CRLF
	if !bytes.HasSuffix(body, []byte("\r\n")) {
		body = append(body, []byte("\r\n")...)
	}

	return body
}

func canonicalizeBodyRelaxed(body []byte) []byte {
	// Reduce whitespace sequences to single space
	// Remove trailing whitespace from lines
	// Ignore all empty lines at the end

	// Convert to lines
	lines := bytes.Split(body, []byte("\n"))

	var result []byte
	re := regexp.MustCompile(`[ \t]+`)

	for _, line := range lines {
		// Remove \r if present
		line = bytes.TrimRight(line, "\r")

		// Remove trailing whitespace
		line = bytes.TrimRight(line, " \t")

		// Reduce whitespace sequences to single space
		line = re.ReplaceAll(line, []byte(" "))

		result = append(result, line...)
		result = append(result, []byte("\r\n")...)
	}

	// Remove trailing empty lines
	for bytes.HasSuffix(result, []byte("\r\n\r\n")) {
		result = result[:len(result)-2]
	}

	// Ensure at least one CRLF
	if len(result) == 0 {
		result = []byte("\r\n")
	}

	return result
}

// ComputeBodyHash computes body hash
func ComputeBodyHash(body []byte, canon CanonMode, length int) []byte {
	// Canonicalize body
	canonBody := CanonicalizeBody(body, canon)

	// Truncate if length specified (l= tag)
	if length > 0 && length < len(canonBody) {
		canonBody = canonBody[:length]
	}

	// Compute SHA-256 hash
	hash := sha256.Sum256(canonBody)
	return hash[:]
}

// Verify verifies a DKIM signature
func Verify(ctx context.Context, resolver DNSResolver, message *Message, signature *Signature) (*Result, error) {
	result := &Result{
		Domain:        signature.Domain,
		Selector:      signature.Selector,
		Algorithm:     signature.Algorithm,
		SignatureTime: signature.Timestamp,
	}

	// 1. Fetch public key
	pubKey, err := LookupPublicKey(ctx, resolver, signature.Selector, signature.Domain)
	if err != nil {
		result.Error = err
		return result, nil
	}

	// 2. Verify body hash
	bodyHash := ComputeBodyHash(message.Body, signature.BodyCanon, signature.BodyLength)

	if !bytes.Equal(bodyHash, signature.BodyHash) {
		result.Error = ErrBodyHashMismatch
		result.BodyOK = false
		return result, nil
	}
	result.BodyOK = true

	// 3. Canonicalize headers
	canonHeaders := CanonicalizeHeaders(message.Headers, signature.HeaderCanon, signature.Headers)

	// 4. Add DKIM-Signature header (with b= empty)
	dkimHeader := constructDKIMHeader(signature)
	canonHeaders = append(canonHeaders, dkimHeader...)

	// 5. Verify signature
	valid, err := verifySignature(canonHeaders, signature.Signature, pubKey.PublicKey, signature.Algorithm)
	if err != nil {
		result.Error = err
		return result, nil
	}

	result.Valid = valid
	result.HeadersOK = valid

	return result, nil
}

// constructDKIMHeader constructs DKIM-Signature header with b= empty
func constructDKIMHeader(sig *Signature) []byte {
	var buf bytes.Buffer

	buf.WriteString("dkim-signature:")

	// Reconstruct header in canonical order
	tags := []string{
		fmt.Sprintf("v=%s", sig.Version),
		fmt.Sprintf("a=%s", sig.Algorithm),
		"b=", // Empty signature
		fmt.Sprintf("bh=%s", base64.StdEncoding.EncodeToString(sig.BodyHash)),
		fmt.Sprintf("c=%s/%s", sig.HeaderCanon, sig.BodyCanon),
		fmt.Sprintf("d=%s", sig.Domain),
		fmt.Sprintf("h=%s", strings.Join(sig.Headers, ":")),
		fmt.Sprintf("s=%s", sig.Selector),
	}

	buf.WriteString(strings.Join(tags, "; "))

	return buf.Bytes()
}

// verifySignature verifies cryptographic signature
func verifySignature(data, signature []byte, pubKey interface{}, algo Algorithm) (bool, error) {
	switch algo {
	case AlgorithmRSASHA256:
		rsaKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return false, ErrInvalidKeyType
		}

		hash := sha256.Sum256(data)
		err := rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, hash[:], signature)
		return err == nil, nil

	case AlgorithmED25519SHA256:
		ed25519Key, ok := pubKey.(ed25519.PublicKey)
		if !ok {
			return false, ErrInvalidKeyType
		}

		hash := sha256.Sum256(data)
		return ed25519.Verify(ed25519Key, hash[:], signature), nil

	case AlgorithmRSASHA1:
		// SHA1 is deprecated and insecure
		return false, ErrInvalidAlgorithm

	default:
		return false, ErrInvalidAlgorithm
	}
}

// VerifyMessage verifies all DKIM signatures in a message
func VerifyMessage(ctx context.Context, resolver DNSResolver, message *Message) ([]Result, error) {
	var results []Result

	// Find all DKIM-Signature headers
	for _, header := range message.Headers {
		if strings.ToLower(header.Name) == "dkim-signature" {
			sig, err := ParseSignature(header.Value)
			if err != nil {
				// Include failed parse as a result
				results = append(results, Result{
					Valid: false,
					Error: err,
				})
				continue
			}

			result, err := Verify(ctx, resolver, message, sig)
			if err != nil {
				return results, err
			}

			results = append(results, *result)
		}
	}

	if len(results) == 0 {
		return nil, ErrNoSignature
	}

	return results, nil
}
