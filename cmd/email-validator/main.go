// email-validator is a command-line tool for validating email messages using SPF, DKIM, and DMARC.
//
// This tool provides comprehensive email authentication by combining:
//   - SPF (Sender Policy Framework) verification
//   - DKIM (DomainKeys Identified Mail) signature verification
//   - DMARC (Domain-based Message Authentication, Reporting & Conformance) policy evaluation
//
// Usage:
//   email-validator [flags]
//
// Flags:
//   -ip string         IP address of the sending mail server (required for SPF)
//   -from string       Envelope sender address (MAIL FROM) (required)
//   -header-from string Header From address (required for DMARC)
//   -file string       Path to email file (EML format)
//   -verbose           Show detailed authentication results
//   -json              Output results in JSON format
//   -timeout duration  DNS lookup timeout (default: 10s)
//
// Examples:
//
//   # Validate email from file
//   email-validator -ip 192.0.2.1 -from sender@example.com -file message.eml
//
//   # Quick SPF check
//   email-validator -ip 192.0.2.1 -from sender@example.com
//
//   # Full authentication with verbose output
//   email-validator -ip 192.0.2.1 -from sender@example.com -file message.eml -verbose
//
//   # JSON output for automation
//   email-validator -ip 192.0.2.1 -from sender@example.com -file message.eml -json
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/mail"
	"os"
	"strings"
	"time"

	"github.com/asggo/spf/auth"
	"github.com/asggo/spf/dkim"
	"github.com/asggo/spf/spf"
)

// Config holds the CLI configuration
type Config struct {
	IP         string
	From       string
	HeaderFrom string
	File       string
	Verbose    bool
	JSON       bool
	Timeout    time.Duration
}

// ValidationResult represents the complete validation output
type ValidationResult struct {
	Authenticated        bool                  `json:"authenticated"`
	Reason               string                `json:"reason,omitempty"`
	SPF                  SPFResultOutput       `json:"spf"`
	DKIM                 []DKIMResultOutput    `json:"dkim"`
	DMARC                DMARCResultOutput     `json:"dmarc"`
	AuthenticationHeader string                `json:"authentication_header,omitempty"`
	RecommendedAction    string                `json:"recommended_action"`
}

type SPFResultOutput struct {
	Result string `json:"result"`
	Domain string `json:"domain"`
	Error  string `json:"error,omitempty"`
}

type DKIMResultOutput struct {
	Valid    bool   `json:"valid"`
	Domain   string `json:"domain"`
	Selector string `json:"selector"`
	Error    string `json:"error,omitempty"`
}

type DMARCResultOutput struct {
	Policy      string `json:"policy"`
	Disposition string `json:"disposition"`
	SPFAligned  bool   `json:"spf_aligned"`
	DKIMAligned bool   `json:"dkim_aligned"`
	Domain      string `json:"domain"`
	Error       string `json:"error,omitempty"`
}

func main() {
	config := parseFlags()

	if err := validateConfig(config); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		flag.Usage()
		os.Exit(1)
	}

	result, err := performValidation(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Validation error: %v\n", err)
		os.Exit(1)
	}

	if config.JSON {
		outputJSON(result)
	} else {
		outputHuman(result, config.Verbose)
	}

	// Exit with appropriate code
	if !result.Authenticated {
		os.Exit(1)
	}
}

func parseFlags() *Config {
	config := &Config{}

	flag.StringVar(&config.IP, "ip", "", "IP address of the sending mail server")
	flag.StringVar(&config.From, "from", "", "Envelope sender address (MAIL FROM)")
	flag.StringVar(&config.HeaderFrom, "header-from", "", "Header From address (optional, extracted from email if not provided)")
	flag.StringVar(&config.File, "file", "", "Path to email file (EML format)")
	flag.BoolVar(&config.Verbose, "verbose", false, "Show detailed authentication results")
	flag.BoolVar(&config.JSON, "json", false, "Output results in JSON format")
	flag.DurationVar(&config.Timeout, "timeout", 10*time.Second, "DNS lookup timeout")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "email-validator - Email Authentication Tool (SPF + DKIM + DMARC)\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  email-validator [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  # Validate email from file\n")
		fmt.Fprintf(os.Stderr, "  email-validator -ip 192.0.2.1 -from sender@example.com -file message.eml\n\n")
		fmt.Fprintf(os.Stderr, "  # Quick SPF check\n")
		fmt.Fprintf(os.Stderr, "  email-validator -ip 192.0.2.1 -from sender@example.com\n\n")
		fmt.Fprintf(os.Stderr, "  # JSON output\n")
		fmt.Fprintf(os.Stderr, "  email-validator -ip 192.0.2.1 -from sender@example.com -file message.eml -json\n")
	}

	flag.Parse()
	return config
}

func validateConfig(config *Config) error {
	if config.IP == "" {
		return fmt.Errorf("IP address is required (-ip)")
	}
	if config.From == "" {
		return fmt.Errorf("envelope sender is required (-from)")
	}
	return nil
}

func performValidation(config *Config) (*ValidationResult, error) {
	// Create DNS resolver with caching
	baseResolver := spf.NewDefaultResolver()
	resolver := spf.NewCachedResolver(baseResolver, 5*time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)
	defer cancel()

	// Parse email message if file provided
	var message *auth.EmailMessage
	if config.File != "" {
		var err error
		message, err = parseEmailFile(config.File, config.IP, config.From)
		if err != nil {
			return nil, fmt.Errorf("failed to parse email file: %w", err)
		}
	} else {
		// Create minimal message for SPF-only check
		headerFrom := config.HeaderFrom
		if headerFrom == "" {
			headerFrom = config.From
		}

		message = &auth.EmailMessage{
			Headers: []dkim.Header{
				{Name: "From", Value: headerFrom},
			},
			Body:           []byte(""),
			EnvelopeSender: config.From,
			ClientIP:       config.IP,
		}
	}

	// Perform authentication
	authResult, err := auth.Authenticate(ctx, resolver, message)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	// Convert to output format
	result := convertToOutput(authResult)
	return result, nil
}

func parseEmailFile(filename, ip, envelopeSender string) (*auth.EmailMessage, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Parse email
	msg, err := mail.ReadMessage(file)
	if err != nil {
		return nil, fmt.Errorf("failed to parse email: %w", err)
	}

	// Read body
	body, err := io.ReadAll(msg.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %w", err)
	}

	// Convert headers
	var headers []dkim.Header
	for name, values := range msg.Header {
		for _, value := range values {
			headers = append(headers, dkim.Header{
				Name:  name,
				Value: value,
			})
		}
	}

	return &auth.EmailMessage{
		Headers:        headers,
		Body:           body,
		EnvelopeSender: envelopeSender,
		ClientIP:       ip,
	}, nil
}

func convertToOutput(authResult *auth.AuthenticationResult) *ValidationResult {
	result := &ValidationResult{
		Authenticated:        authResult.Authenticated,
		Reason:               authResult.Reason,
		AuthenticationHeader: authResult.AuthResultsHeader,
	}

	// SPF
	result.SPF = SPFResultOutput{
		Result: string(authResult.SPF.Result),
		Domain: authResult.SPF.Domain,
	}
	if authResult.SPF.Error != nil {
		result.SPF.Error = authResult.SPF.Error.Error()
	}

	// DKIM
	for _, dkim := range authResult.DKIM {
		dkimOutput := DKIMResultOutput{
			Valid:    dkim.Valid,
			Domain:   dkim.Domain,
			Selector: dkim.Selector,
		}
		if dkim.Error != nil {
			dkimOutput.Error = dkim.Error.Error()
		}
		result.DKIM = append(result.DKIM, dkimOutput)
	}

	// DMARC
	result.DMARC = DMARCResultOutput{
		Policy:      string(authResult.DMARC.Policy),
		Disposition: string(authResult.DMARC.Disposition),
		SPFAligned:  authResult.DMARC.SPFAligned,
		DKIMAligned: authResult.DMARC.DKIMAligned,
		Domain:      authResult.DMARC.Domain,
	}
	if authResult.DMARC.Error != nil {
		result.DMARC.Error = authResult.DMARC.Error.Error()
	}

	// Recommended action
	result.RecommendedAction = determineAction(authResult)

	return result
}

func determineAction(authResult *auth.AuthenticationResult) string {
	if authResult.Authenticated {
		return "DELIVER"
	}

	switch authResult.DMARC.Disposition {
	case "reject":
		return "REJECT"
	case "quarantine":
		return "QUARANTINE"
	default:
		return "DELIVER_WITH_WARNING"
	}
}

func outputJSON(result *ValidationResult) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
		os.Exit(1)
	}
}

func outputHuman(result *ValidationResult, verbose bool) {
	// Header
	fmt.Println("╔════════════════════════════════════════════════════════════════╗")
	fmt.Println("║           EMAIL AUTHENTICATION VALIDATION RESULTS              ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Overall result
	if result.Authenticated {
		fmt.Println("✅ AUTHENTICATION: PASS")
	} else {
		fmt.Println("❌ AUTHENTICATION: FAIL")
	}

	if result.Reason != "" {
		fmt.Printf("   Reason: %s\n", result.Reason)
	}
	fmt.Println()

	// SPF
	fmt.Println("┌─ SPF (Sender Policy Framework)")
	spfSymbol := getResultSymbol(result.SPF.Result)
	fmt.Printf("│  Result: %s %s\n", spfSymbol, result.SPF.Result)
	if result.SPF.Domain != "" {
		fmt.Printf("│  Domain: %s\n", result.SPF.Domain)
	}
	if verbose && result.SPF.Error != "" {
		fmt.Printf("│  Error:  %s\n", result.SPF.Error)
	}
	fmt.Println("└─")
	fmt.Println()

	// DKIM
	fmt.Println("┌─ DKIM (DomainKeys Identified Mail)")
	if len(result.DKIM) == 0 {
		fmt.Println("│  Result: ⚠️  No DKIM signatures found")
	} else {
		for i, dkim := range result.DKIM {
			symbol := "❌"
			status := "INVALID"
			if dkim.Valid {
				symbol = "✅"
				status = "VALID"
			}
			fmt.Printf("│  Signature #%d: %s %s\n", i+1, symbol, status)
			if dkim.Domain != "" {
				fmt.Printf("│    Domain:   %s\n", dkim.Domain)
			}
			if dkim.Selector != "" {
				fmt.Printf("│    Selector: %s\n", dkim.Selector)
			}
			if verbose && dkim.Error != "" {
				fmt.Printf("│    Error:    %s\n", dkim.Error)
			}
		}
	}
	fmt.Println("└─")
	fmt.Println()

	// DMARC
	fmt.Println("┌─ DMARC (Domain-based Message Authentication)")
	if result.DMARC.Policy != "" && result.DMARC.Policy != "none" {
		alignmentPass := result.DMARC.SPFAligned || result.DMARC.DKIMAligned
		symbol := "❌"
		if alignmentPass {
			symbol = "✅"
		}
		fmt.Printf("│  Result:     %s ", symbol)
		if alignmentPass {
			fmt.Println("PASS")
		} else {
			fmt.Println("FAIL")
		}
		fmt.Printf("│  Policy:     %s\n", strings.ToUpper(result.DMARC.Policy))
		if result.DMARC.Disposition != "" {
			fmt.Printf("│  Action:     %s\n", strings.ToUpper(result.DMARC.Disposition))
		}
		if result.DMARC.Domain != "" {
			fmt.Printf("│  Domain:     %s\n", result.DMARC.Domain)
		}

		fmt.Println("│  Alignment:")
		spfAlignSymbol := "❌"
		if result.DMARC.SPFAligned {
			spfAlignSymbol = "✅"
		}
		dkimAlignSymbol := "❌"
		if result.DMARC.DKIMAligned {
			dkimAlignSymbol = "✅"
		}
		fmt.Printf("│    SPF:  %s\n", spfAlignSymbol)
		fmt.Printf("│    DKIM: %s\n", dkimAlignSymbol)
	} else {
		fmt.Println("│  Result: ⚠️  No DMARC policy found")
	}
	if verbose && result.DMARC.Error != "" {
		fmt.Printf("│  Error:  %s\n", result.DMARC.Error)
	}
	fmt.Println("└─")
	fmt.Println()

	// Recommended action
	fmt.Println("┌─ RECOMMENDED ACTION")
	fmt.Printf("│  %s\n", getActionWithIcon(result.RecommendedAction))
	fmt.Println("└─")
	fmt.Println()

	// Authentication-Results header
	if verbose && result.AuthenticationHeader != "" {
		fmt.Println("┌─ AUTHENTICATION-RESULTS HEADER")
		// Wrap long header
		wrapped := wrapText(result.AuthenticationHeader, 60)
		for _, line := range strings.Split(wrapped, "\n") {
			fmt.Printf("│  %s\n", line)
		}
		fmt.Println("└─")
		fmt.Println()
	}

	// Final summary
	fmt.Println("═══════════════════════════════════════════════════════════════")
	if result.Authenticated {
		fmt.Println("✅ EMAIL PASSED AUTHENTICATION - SAFE TO DELIVER")
	} else {
		fmt.Println("⚠️  EMAIL FAILED AUTHENTICATION - HANDLE WITH CAUTION")
	}
	fmt.Println("═══════════════════════════════════════════════════════════════")
}

func getResultSymbol(result string) string {
	switch strings.ToLower(result) {
	case "pass":
		return "✅"
	case "fail", "hardfail":
		return "❌"
	case "softfail":
		return "⚠️"
	case "neutral":
		return "⚪"
	case "none":
		return "⚫"
	case "temperror", "permerror":
		return "🔴"
	default:
		return "❓"
	}
}

func getActionWithIcon(action string) string {
	switch action {
	case "DELIVER":
		return "✅ DELIVER - Email passed authentication"
	case "REJECT":
		return "🚫 REJECT - Email should be rejected"
	case "QUARANTINE":
		return "⚠️  QUARANTINE - Move to spam/junk folder"
	case "DELIVER_WITH_WARNING":
		return "⚠️  DELIVER WITH WARNING - Authentication weak or failed"
	default:
		return action
	}
}

func wrapText(text string, width int) string {
	if len(text) <= width {
		return text
	}

	var result strings.Builder
	words := strings.Fields(text)
	lineLen := 0

	for i, word := range words {
		wordLen := len(word)
		if lineLen+wordLen+1 > width {
			result.WriteString("\n")
			lineLen = 0
		} else if i > 0 {
			result.WriteString(" ")
			lineLen++
		}
		result.WriteString(word)
		lineLen += wordLen
	}

	return result.String()
}
