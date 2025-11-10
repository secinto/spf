// Package auth provides unified email authentication combining SPF, DKIM, and DMARC.
//
// This package orchestrates the complete email authentication workflow:
// 1. SPF verification using envelope sender (MAIL FROM)
// 2. DKIM signature verification
// 3. DMARC policy evaluation and alignment checking
// 4. Final authentication decision based on DMARC policy
//
// Example usage:
//
//	ctx := context.Background()
//	resolver := spf.NewDefaultResolver()
//
//	// Parse email message
//	message := &auth.EmailMessage{
//	    Headers: []dkim.Header{
//	        {Name: "From", Value: "sender@example.com"},
//	        {Name: "DKIM-Signature", Value: "..."},
//	    },
//	    Body:         []byte("Email body"),
//	    EnvelopeSender: "bounce@example.com",
//	    ClientIP:       "192.0.2.1",
//	}
//
//	// Authenticate
//	result, err := auth.Authenticate(ctx, resolver, message)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Check result
//	if result.Authenticated {
//	    fmt.Println("Email authenticated successfully")
//	} else {
//	    fmt.Printf("Authentication failed: %s\n", result.Reason)
//	}
package auth

import (
	"context"
	"fmt"
	"net/mail"
	"strings"

	"github.com/asggo/spf/dkim"
	"github.com/asggo/spf/dmarc"
	spflib "github.com/asggo/spf/spf"
)

// DNSResolver provides DNS lookup capabilities for authentication
type DNSResolver interface {
	spflib.DNSResolver
}

// EmailMessage represents an email message to be authenticated
type EmailMessage struct {
	// Headers contains all email headers including DKIM-Signature
	Headers []dkim.Header

	// Body is the complete message body
	Body []byte

	// EnvelopeSender is the SMTP MAIL FROM address (RFC5321.MailFrom)
	EnvelopeSender string

	// ClientIP is the IP address of the sending MTA
	ClientIP string

	// HELO/EHLO domain (optional, for SPF)
	HelloDomain string
}

// AuthenticationResult contains the complete authentication result
type AuthenticationResult struct {
	// Authenticated indicates if the message passed authentication
	Authenticated bool

	// Reason provides explanation if authentication failed
	Reason string

	// SPF result
	SPF SPFResult

	// DKIM results (one per signature)
	DKIM []DKIMResult

	// DMARC result
	DMARC DMARCResult

	// AuthenticationResults header value (RFC 8601)
	AuthResultsHeader string
}

// SPFResult contains SPF verification result
type SPFResult struct {
	Result spflib.Result
	Domain string
	Error  error
}

// DKIMResult contains DKIM verification result
type DKIMResult struct {
	Valid    bool
	Domain   string
	Selector string
	Error    error
}

// DMARCResult contains DMARC evaluation result
type DMARCResult struct {
	Policy      dmarc.Policy
	Disposition dmarc.Disposition
	SPFAligned  bool
	DKIMAligned bool
	Domain      string
	Error       error
}

// Authenticate performs complete email authentication (SPF + DKIM + DMARC)
func Authenticate(ctx context.Context, resolver DNSResolver, message *EmailMessage) (*AuthenticationResult, error) {
	result := &AuthenticationResult{
		Authenticated: false,
	}

	// Extract Header From domain for DMARC
	headerFrom, err := extractHeaderFrom(message.Headers)
	if err != nil {
		return nil, fmt.Errorf("failed to extract From header: %w", err)
	}

	headerFromDomain := extractDomain(headerFrom)
	if headerFromDomain == "" {
		return nil, fmt.Errorf("invalid From header: %s", headerFrom)
	}

	// 1. SPF Verification
	spfResult := performSPF(ctx, resolver, message)
	result.SPF = spfResult

	// 2. DKIM Verification
	dkimResults := performDKIM(ctx, resolver, message)
	result.DKIM = dkimResults

	// 3. DMARC Evaluation
	dmarcResult := performDMARC(ctx, resolver, headerFrom, message.EnvelopeSender, spfResult, dkimResults)
	result.DMARC = dmarcResult

	// 4. Determine final authentication status based on DMARC
	result.Authenticated, result.Reason = evaluateAuthentication(spfResult, dkimResults, dmarcResult)

	// 5. Generate Authentication-Results header
	result.AuthResultsHeader = generateAuthResultsHeader(result, headerFromDomain)

	return result, nil
}

// performSPF executes SPF verification
func performSPF(ctx context.Context, resolver DNSResolver, message *EmailMessage) SPFResult {
	config := &spflib.Config{
		DNSResolver: resolver,
	}

	domain := extractDomain(message.EnvelopeSender)
	if domain == "" {
		return SPFResult{
			Result: spflib.None,
			Domain: "",
			Error:  fmt.Errorf("no domain in envelope sender"),
		}
	}

	result, err := spflib.SPFTestContext(ctx, config, message.ClientIP, message.EnvelopeSender)

	return SPFResult{
		Result: result,
		Domain: domain,
		Error:  err,
	}
}

// performDKIM executes DKIM verification for all signatures
func performDKIM(ctx context.Context, resolver DNSResolver, message *EmailMessage) []DKIMResult {
	var results []DKIMResult

	// Create DKIM message
	dkimMessage := &dkim.Message{
		Headers: message.Headers,
		Body:    message.Body,
	}

	// Verify all DKIM signatures
	dkimVerifyResults, err := dkim.VerifyMessage(ctx, resolver, dkimMessage)
	if err != nil {
		results = append(results, DKIMResult{
			Valid: false,
			Error: err,
		})
		return results
	}

	// Convert DKIM results
	for _, vr := range dkimVerifyResults {
		results = append(results, DKIMResult{
			Valid:    vr.Valid,
			Domain:   vr.Domain,
			Selector: vr.Selector,
			Error:    vr.Error,
		})
	}

	if len(results) == 0 {
		results = append(results, DKIMResult{
			Valid: false,
			Error: fmt.Errorf("no DKIM signatures found"),
		})
	}

	return results
}

// performDMARC executes DMARC policy evaluation
func performDMARC(ctx context.Context, resolver DNSResolver, headerFrom, envelopeSender string, spfResult SPFResult, dkimResults []DKIMResult) DMARCResult {
	config := &dmarc.Config{
		Resolver: resolver,
	}

	// Collect DKIM domains
	var dkimDomains []string
	for _, dr := range dkimResults {
		if dr.Valid {
			dkimDomains = append(dkimDomains, dr.Domain)
		}
	}

	// SPF pass determination
	spfPass := spfResult.Result == spflib.Pass

	// Evaluate DMARC
	dmarcEval, err := dmarc.Evaluate(ctx, config, headerFrom, envelopeSender, spfPass, dkimDomains)
	if err != nil {
		headerFromDomain := extractDomain(headerFrom)
		return DMARCResult{
			Policy: dmarc.PolicyNone,
			Error:  err,
			Domain: headerFromDomain,
		}
	}

	return DMARCResult{
		Policy:      dmarcEval.AppliedPolicy,
		Disposition: dmarcEval.Disposition,
		SPFAligned:  dmarcEval.SPFAligned,
		DKIMAligned: dmarcEval.DKIMAligned,
		Domain:      dmarcEval.HeaderFromDomain,
		Error:       nil,
	}
}

// evaluateAuthentication determines final authentication status
func evaluateAuthentication(spfResult SPFResult, dkimResults []DKIMResult, dmarcResult DMARCResult) (bool, string) {
	// If DMARC policy exists, follow it
	if dmarcResult.Policy != dmarc.PolicyNone {
		// Check if DMARC passed (either SPF or DKIM aligned)
		if dmarcResult.SPFAligned || dmarcResult.DKIMAligned {
			return true, "DMARC pass"
		}

		// DMARC failed - check disposition
		switch dmarcResult.Disposition {
		case dmarc.DispositionReject:
			return false, "DMARC policy=reject"
		case dmarc.DispositionQuarantine:
			return false, "DMARC policy=quarantine"
		default:
			return false, "DMARC alignment failed"
		}
	}

	// No DMARC policy - fallback to SPF/DKIM only
	if spfResult.Result == spflib.Pass {
		return true, "SPF pass (no DMARC)"
	}

	for _, dr := range dkimResults {
		if dr.Valid {
			return true, "DKIM pass (no DMARC)"
		}
	}

	// Both failed
	reasons := []string{}
	if spfResult.Result != spflib.Pass {
		reasons = append(reasons, fmt.Sprintf("SPF %s", spfResult.Result))
	}
	if len(dkimResults) == 0 || !anyDKIMValid(dkimResults) {
		reasons = append(reasons, "DKIM fail")
	}

	return false, strings.Join(reasons, ", ")
}

// anyDKIMValid checks if any DKIM signature is valid
func anyDKIMValid(results []DKIMResult) bool {
	for _, r := range results {
		if r.Valid {
			return true
		}
	}
	return false
}

// generateAuthResultsHeader generates RFC 8601 Authentication-Results header
func generateAuthResultsHeader(result *AuthenticationResult, domain string) string {
	var parts []string

	// SPF result
	spfStatus := strings.ToLower(string(result.SPF.Result))
	if result.SPF.Domain != "" {
		parts = append(parts, fmt.Sprintf("spf=%s smtp.mailfrom=%s", spfStatus, result.SPF.Domain))
	} else {
		parts = append(parts, fmt.Sprintf("spf=%s", spfStatus))
	}

	// DKIM results
	if len(result.DKIM) > 0 {
		for _, dr := range result.DKIM {
			if dr.Domain != "" {
				status := "fail"
				if dr.Valid {
					status = "pass"
				}
				parts = append(parts, fmt.Sprintf("dkim=%s header.d=%s header.s=%s", status, dr.Domain, dr.Selector))
			}
		}
	} else {
		parts = append(parts, "dkim=none")
	}

	// DMARC result
	if result.DMARC.Policy != dmarc.PolicyNone {
		dmarcStatus := "fail"
		if result.DMARC.SPFAligned || result.DMARC.DKIMAligned {
			dmarcStatus = "pass"
		}
		parts = append(parts, fmt.Sprintf("dmarc=%s header.from=%s", dmarcStatus, result.DMARC.Domain))
	}

	return "Authentication-Results: localhost; " + strings.Join(parts, "; ")
}

// extractHeaderFrom extracts the From header value
func extractHeaderFrom(headers []dkim.Header) (string, error) {
	for _, h := range headers {
		if strings.EqualFold(h.Name, "from") {
			return h.Value, nil
		}
	}
	return "", fmt.Errorf("From header not found")
}

// extractDomain extracts domain from email address
func extractDomain(email string) string {
	// Try to parse as RFC 5322 address
	addr, err := mail.ParseAddress(email)
	if err != nil {
		// Try simple split
		parts := strings.Split(email, "@")
		if len(parts) == 2 {
			return strings.ToLower(strings.TrimSpace(parts[1]))
		}
		return ""
	}

	parts := strings.Split(addr.Address, "@")
	if len(parts) == 2 {
		return strings.ToLower(strings.TrimSpace(parts[1]))
	}
	return ""
}
