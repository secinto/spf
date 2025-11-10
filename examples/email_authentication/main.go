// Package main demonstrates comprehensive email authentication using SPF, DKIM, and DMARC.
//
// This example shows how to authenticate an email message using the unified auth package.
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/asggo/spf/spf"
	"github.com/asggo/spf/auth"
	"github.com/asggo/spf/dkim"
)

func main() {
	// Example 1: Authenticate a simple email message
	authenticateSimpleEmail()

	// Example 2: Authenticate email with DKIM signature
	authenticateEmailWithDKIM()

	// Example 3: Handle authentication failures
	handleAuthenticationFailure()
}

func authenticateSimpleEmail() {
	fmt.Println("=== Example 1: Simple Email Authentication ===")

	// Create a DNS resolver
	resolver := spf.NewDefaultResolver()

	// Prepare email message
	message := &auth.EmailMessage{
		Headers: []dkim.Header{
			{Name: "From", Value: "sender@example.com"},
			{Name: "To", Value: "recipient@example.com"},
			{Name: "Subject", Value: "Test Message"},
			{Name: "Date", Value: "Mon, 1 Jan 2024 12:00:00 +0000"},
		},
		Body:           []byte("This is a test message.\r\n"),
		EnvelopeSender: "sender@example.com",
		ClientIP:       "192.0.2.1", // IP from which the email was sent
		HelloDomain:    "mail.example.com",
	}

	// Authenticate the message
	ctx := context.Background()
	result, err := auth.Authenticate(ctx, resolver, message)
	if err != nil {
		log.Fatalf("Authentication error: %v", err)
	}

	// Display results
	fmt.Printf("Authenticated: %v\n", result.Authenticated)
	fmt.Printf("Reason: %s\n", result.Reason)
	fmt.Printf("SPF Result: %s (domain: %s)\n", result.SPF.Result, result.SPF.Domain)
	fmt.Printf("DKIM Results: %d signature(s)\n", len(result.DKIM))
	for i, dkim := range result.DKIM {
		fmt.Printf("  DKIM #%d: Valid=%v, Domain=%s, Selector=%s\n",
			i+1, dkim.Valid, dkim.Domain, dkim.Selector)
	}
	fmt.Printf("DMARC Policy: %s\n", result.DMARC.Policy)
	fmt.Printf("DMARC SPF Aligned: %v\n", result.DMARC.SPFAligned)
	fmt.Printf("DMARC DKIM Aligned: %v\n", result.DMARC.DKIMAligned)
	fmt.Printf("\nAuthentication-Results Header:\n%s\n\n", result.AuthResultsHeader)
}

func authenticateEmailWithDKIM() {
	fmt.Println("=== Example 2: Email with DKIM Signature ===")

	resolver := spf.NewDefaultResolver()

	// Email with DKIM signature
	message := &auth.EmailMessage{
		Headers: []dkim.Header{
			{Name: "DKIM-Signature", Value: "v=1; a=rsa-sha256; d=example.com; s=default; c=relaxed/simple; h=from:to:subject; bh=...; b=..."},
			{Name: "From", Value: "Alice <alice@example.com>"},
			{Name: "To", Value: "Bob <bob@example.com>"},
			{Name: "Subject", Value: "Important Message"},
		},
		Body:           []byte("Please review this important message.\r\n"),
		EnvelopeSender: "alice@example.com",
		ClientIP:       "192.0.2.1",
	}

	ctx := context.Background()
	result, err := auth.Authenticate(ctx, resolver, message)
	if err != nil {
		log.Fatalf("Authentication error: %v", err)
	}

	fmt.Printf("Authenticated: %v\n", result.Authenticated)
	fmt.Printf("Authentication-Results: %s\n\n", result.AuthResultsHeader)
}

func handleAuthenticationFailure() {
	fmt.Println("=== Example 3: Handling Authentication Failures ===")

	resolver := spf.NewDefaultResolver()

	// Email from unauthorized IP
	message := &auth.EmailMessage{
		Headers: []dkim.Header{
			{Name: "From", Value: "sender@example.com"},
			{Name: "To", Value: "recipient@example.com"},
			{Name: "Subject", Value: "Suspicious Message"},
		},
		Body:           []byte("This might be spam.\r\n"),
		EnvelopeSender: "sender@example.com",
		ClientIP:       "198.51.100.1", // Unauthorized IP
	}

	ctx := context.Background()
	result, err := auth.Authenticate(ctx, resolver, message)
	if err != nil {
		log.Fatalf("Authentication error: %v", err)
	}

	// Handle based on authentication result
	if !result.Authenticated {
		fmt.Printf("⚠️  Authentication FAILED\n")
		fmt.Printf("Reason: %s\n", result.Reason)

		// Check DMARC policy for recommended action
		switch result.DMARC.Disposition {
		case "reject":
			fmt.Println("Action: REJECT the message")
		case "quarantine":
			fmt.Println("Action: Move to spam/quarantine folder")
		default:
			fmt.Println("Action: Deliver with warning")
		}

		// Log details for analysis
		fmt.Printf("\nDetails:\n")
		fmt.Printf("- SPF: %s\n", result.SPF.Result)
		fmt.Printf("- DKIM: %d valid signature(s)\n", countValidDKIM(result.DKIM))
		fmt.Printf("- DMARC Policy: %s\n", result.DMARC.Policy)
		fmt.Printf("- SPF Aligned: %v\n", result.DMARC.SPFAligned)
		fmt.Printf("- DKIM Aligned: %v\n", result.DMARC.DKIMAligned)
	} else {
		fmt.Println("✓ Authentication PASSED")
	}
	fmt.Println()
}

func countValidDKIM(results []auth.DKIMResult) int {
	count := 0
	for _, r := range results {
		if r.Valid {
			count++
		}
	}
	return count
}

// Example 4: Custom handling for different scenarios
func customAuthenticationHandling() {
	fmt.Println("=== Example 4: Custom Authentication Handling ===")

	resolver := spf.NewDefaultResolver()

	message := &auth.EmailMessage{
		Headers: []dkim.Header{
			{Name: "From", Value: "notification@bank.example.com"},
			{Name: "To", Value: "customer@email.com"},
			{Name: "Subject", Value: "Account Alert"},
		},
		Body:           []byte("Your account requires attention.\r\n"),
		EnvelopeSender: "bounce@bank.example.com",
		ClientIP:       "192.0.2.50",
	}

	ctx := context.Background()
	result, err := auth.Authenticate(ctx, resolver, message)
	if err != nil {
		log.Fatalf("Authentication error: %v", err)
	}

	// Strict authentication for financial emails
	if !result.Authenticated {
		fmt.Println("🚨 SECURITY ALERT: Financial email failed authentication")
		fmt.Printf("This appears to be phishing. Reason: %s\n", result.Reason)
		fmt.Println("RECOMMENDED ACTION: REJECT and report as phishing")
	} else {
		// Additional checks for high-security domains
		if result.DMARC.Policy == "reject" {
			fmt.Println("✓ Strong authentication: DMARC policy=reject enforced")
		}

		if countValidDKIM(result.DKIM) > 0 && result.SPF.Result == spf.Pass {
			fmt.Println("✓ Excellent: Both SPF and DKIM passed")
		}

		fmt.Println("Message authenticated successfully - safe to deliver")
	}
	fmt.Println()
}

// Example 5: Batch email authentication
func batchAuthentication() {
	fmt.Println("=== Example 5: Batch Email Authentication ===")

	resolver := spf.NewDefaultResolver()
	ctx := context.Background()

	// Simulate multiple emails
	emails := []struct {
		from   string
		ip     string
		hasDKIM bool
	}{
		{"legitimate@example.com", "192.0.2.1", true},
		{"spammer@spam.example", "198.51.100.99", false},
		{"newsletter@news.example.com", "192.0.2.100", true},
	}

	passed := 0
	failed := 0

	for i, email := range emails {
		message := &auth.EmailMessage{
			Headers: []dkim.Header{
				{Name: "From", Value: email.from},
				{Name: "To", Value: "user@domain.com"},
				{Name: "Subject", Value: fmt.Sprintf("Message %d", i+1)},
			},
			Body:           []byte("Test message.\r\n"),
			EnvelopeSender: email.from,
			ClientIP:       email.ip,
		}

		result, err := auth.Authenticate(ctx, resolver, message)
		if err != nil {
			fmt.Printf("Email %d: Error - %v\n", i+1, err)
			continue
		}

		if result.Authenticated {
			passed++
			fmt.Printf("Email %d from %s: ✓ PASS\n", i+1, email.from)
		} else {
			failed++
			fmt.Printf("Email %d from %s: ✗ FAIL (%s)\n", i+1, email.from, result.Reason)
		}
	}

	fmt.Printf("\nSummary: %d passed, %d failed\n\n", passed, failed)
}
