# Email Authentication Package

The `auth` package provides unified email authentication by orchestrating SPF, DKIM, and DMARC verification in a single, easy-to-use API.

## Features

- **Complete Email Authentication**: Combines SPF, DKIM, and DMARC checks
- **RFC Compliance**: Implements RFC 7208 (SPF), RFC 6376 (DKIM), and RFC 7489 (DMARC)
- **Simple API**: Single function call performs all authentication checks
- **Detailed Results**: Provides comprehensive authentication status and reasoning
- **Authentication-Results Header**: Generates RFC 8601 compliant headers
- **Context Support**: Supports timeouts and cancellation
- **Production Ready**: Comprehensive test coverage with real-world scenarios

## Installation

```bash
go get github.com/asggo/spf
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/asggo/spf"
    "github.com/asggo/spf/auth"
    "github.com/asggo/spf/dkim"
)

func main() {
    // Create DNS resolver
    resolver := spf.NewDefaultResolver()

    // Prepare email message
    message := &auth.EmailMessage{
        Headers: []dkim.Header{
            {Name: "From", Value: "sender@example.com"},
            {Name: "To", Value: "recipient@example.com"},
            {Name: "Subject", Value: "Test Message"},
        },
        Body:           []byte("Message body\r\n"),
        EnvelopeSender: "sender@example.com",
        ClientIP:       "192.0.2.1",
    }

    // Authenticate
    ctx := context.Background()
    result, err := auth.Authenticate(ctx, resolver, message)
    if err != nil {
        log.Fatal(err)
    }

    // Check result
    if result.Authenticated {
        fmt.Println("✓ Email authenticated successfully")
    } else {
        fmt.Printf("✗ Authentication failed: %s\n", result.Reason)
    }

    // Add Authentication-Results header to email
    fmt.Println(result.AuthResultsHeader)
}
```

## Authentication Workflow

The `Authenticate()` function performs the following steps in order:

1. **SPF Verification**
   - Validates the envelope sender (MAIL FROM) against SPF record
   - Checks if the sending IP is authorized
   - Returns: Pass, Fail, SoftFail, Neutral, None, TempError, PermError

2. **DKIM Verification**
   - Verifies all DKIM-Signature headers in the message
   - Checks cryptographic signatures (RSA-SHA256, ED25519-SHA256)
   - Validates body hash and header signatures
   - Returns: Valid/Invalid for each signature

3. **DMARC Evaluation**
   - Looks up DMARC policy for the header From domain
   - Checks identifier alignment for SPF and DKIM
   - Determines policy action (none, quarantine, reject)
   - Returns: Pass/Fail with policy and disposition

4. **Final Decision**
   - Combines results based on DMARC policy
   - Generates Authentication-Results header
   - Provides actionable recommendation

## API Reference

### Types

#### EmailMessage

Represents an email message to be authenticated:

```go
type EmailMessage struct {
    // Email headers including DKIM-Signature
    Headers []dkim.Header

    // Complete message body
    Body []byte

    // SMTP MAIL FROM address (envelope sender)
    EnvelopeSender string

    // IP address of sending MTA
    ClientIP string

    // HELO/EHLO domain (optional)
    HelloDomain string
}
```

#### AuthenticationResult

Contains the complete authentication result:

```go
type AuthenticationResult struct {
    // Overall authentication status
    Authenticated bool

    // Explanation if authentication failed
    Reason string

    // SPF verification result
    SPF SPFResult

    // DKIM verification results (one per signature)
    DKIM []DKIMResult

    // DMARC evaluation result
    DMARC DMARCResult

    // RFC 8601 Authentication-Results header
    AuthResultsHeader string
}
```

#### SPFResult

```go
type SPFResult struct {
    Result spf.Result  // Pass, Fail, SoftFail, etc.
    Domain string      // Domain that was checked
    Error  error       // Error if verification failed
}
```

#### DKIMResult

```go
type DKIMResult struct {
    Valid    bool     // Signature is valid
    Domain   string   // DKIM signing domain
    Selector string   // DKIM selector used
    Error    error    // Error if verification failed
}
```

#### DMARCResult

```go
type DMARCResult struct {
    Policy      dmarc.Policy       // none, quarantine, reject
    Disposition dmarc.Disposition  // Recommended action
    SPFAligned  bool              // SPF identifier aligned
    DKIMAligned bool              // DKIM identifier aligned
    Domain      string            // Domain checked
    Error       error             // Error if evaluation failed
}
```

### Functions

#### Authenticate

```go
func Authenticate(ctx context.Context, resolver DNSResolver, message *EmailMessage) (*AuthenticationResult, error)
```

Performs complete email authentication combining SPF, DKIM, and DMARC.

**Parameters:**
- `ctx`: Context for timeout and cancellation
- `resolver`: DNS resolver implementing DNSResolver interface
- `message`: Email message to authenticate

**Returns:**
- `*AuthenticationResult`: Complete authentication result
- `error`: Error if authentication cannot be performed (e.g., missing From header)

**Example:**

```go
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()

result, err := auth.Authenticate(ctx, resolver, message)
if err != nil {
    return fmt.Errorf("authentication failed: %w", err)
}
```

## Authentication Scenarios

### Scenario 1: All Pass (Best Case)

```
SPF: Pass
DKIM: Valid signature present
DMARC: Policy=reject, both aligned
Result: Authenticated = true
Action: Deliver normally
```

### Scenario 2: SPF Fail, DKIM Pass

```
SPF: Fail (wrong IP)
DKIM: Valid signature present
DMARC: Policy=reject, DKIM aligned
Result: Authenticated = true (DKIM saves it)
Action: Deliver normally
```

### Scenario 3: Both SPF and DKIM Fail

```
SPF: Fail
DKIM: No valid signatures
DMARC: Policy=reject
Result: Authenticated = false
Disposition: Reject
Action: Reject the message
```

### Scenario 4: DMARC Quarantine

```
SPF: Fail
DKIM: Invalid or missing
DMARC: Policy=quarantine
Result: Authenticated = false
Disposition: Quarantine
Action: Move to spam folder
```

### Scenario 5: No DMARC Policy

```
SPF: Fail
DKIM: Valid signature present
DMARC: No policy found
Result: Authenticated = true (DKIM only)
Action: Deliver with warning
```

## Best Practices

### 1. Always Use Context with Timeout

```go
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()

result, err := auth.Authenticate(ctx, resolver, message)
```

### 2. Cache DNS Resolver

```go
// Create resolver once and reuse
resolver := spf.NewCachedResolver(
    spf.NewDefaultResolver(),
    1000,              // cache size
    5*time.Minute,     // TTL
)

// Use for multiple authentications
for _, msg := range messages {
    result, err := auth.Authenticate(ctx, resolver, msg)
    // ...
}
```

### 3. Handle All Error Cases

```go
result, err := auth.Authenticate(ctx, resolver, message)
if err != nil {
    // Fatal error (e.g., missing From header)
    return err
}

if !result.Authenticated {
    // Check specific failure reasons
    if result.DMARC.Error != nil {
        log.Printf("DMARC lookup failed: %v", result.DMARC.Error)
    }

    // Apply policy
    switch result.DMARC.Disposition {
    case dmarc.DispositionReject:
        return rejectEmail(message)
    case dmarc.DispositionQuarantine:
        return quarantineEmail(message)
    default:
        return deliverWithWarning(message)
    }
}
```

### 4. Log Authentication Results

```go
result, err := auth.Authenticate(ctx, resolver, message)
if err == nil {
    log.Printf("Auth: from=%s ip=%s spf=%s dkim=%d dmarc=%s authenticated=%v",
        message.EnvelopeSender,
        message.ClientIP,
        result.SPF.Result,
        len(result.DKIM),
        result.DMARC.Policy,
        result.Authenticated,
    )
}
```

### 5. Add Authentication-Results Header

```go
result, err := auth.Authenticate(ctx, resolver, message)
if err == nil {
    // Add to email headers before delivery
    email.Headers = append(email.Headers, dkim.Header{
        Name:  "Authentication-Results",
        Value: result.AuthResultsHeader,
    })
}
```

## Performance Considerations

### DNS Lookups

Each authentication performs multiple DNS lookups:
- 1-2 TXT lookups for SPF
- 1+ TXT lookups for DKIM (per signature)
- 1-2 TXT lookups for DMARC

**Recommendation**: Use a caching DNS resolver to reduce latency.

### Parallel Processing

For high-volume email processing:

```go
// Process emails concurrently
sem := make(chan struct{}, 10) // Limit to 10 concurrent
var wg sync.WaitGroup

for _, msg := range messages {
    wg.Add(1)
    go func(m *auth.EmailMessage) {
        defer wg.Done()
        sem <- struct{}{}        // Acquire
        defer func() { <-sem }() // Release

        result, _ := auth.Authenticate(ctx, resolver, m)
        handleResult(result)
    }(msg)
}

wg.Wait()
```

### Memory Usage

- Each authentication allocates ~1-5 KB
- DNS cache can hold thousands of records
- Safe for millions of emails per day

## Security Considerations

### 1. Always Verify DKIM Signatures

DKIM provides the strongest authentication because it cannot be forged (assuming proper key management).

### 2. Respect DMARC Policies

DMARC policies should be enforced:
- `p=reject`: Reject the email
- `p=quarantine`: Mark as spam
- `p=none`: Deliver but monitor

### 3. Be Aware of Alignment Modes

DMARC has two alignment modes:
- **Relaxed**: Organizational domains must match (e.g., `mail.example.com` aligns with `example.com`)
- **Strict**: Exact domain match required

### 4. Handle Edge Cases

- Missing DMARC records (legitimate but less secure)
- Temporary DNS failures (don't reject immediately)
- Multiple DKIM signatures (at least one must pass)
- Forwarded emails (may break SPF, rely on DKIM)

## Troubleshooting

### Authentication Fails Unexpectedly

```go
result, err := auth.Authenticate(ctx, resolver, message)

// Check individual components
fmt.Printf("SPF: %s (domain: %s)\n", result.SPF.Result, result.SPF.Domain)
if result.SPF.Error != nil {
    fmt.Printf("SPF Error: %v\n", result.SPF.Error)
}

for i, dkim := range result.DKIM {
    fmt.Printf("DKIM #%d: Valid=%v, Domain=%s\n", i+1, dkim.Valid, dkim.Domain)
    if dkim.Error != nil {
        fmt.Printf("DKIM Error: %v\n", dkim.Error)
    }
}

fmt.Printf("DMARC: Policy=%s, SPF Aligned=%v, DKIM Aligned=%v\n",
    result.DMARC.Policy, result.DMARC.SPFAligned, result.DMARC.DKIMAligned)
if result.DMARC.Error != nil {
    fmt.Printf("DMARC Error: %v\n", result.DMARC.Error)
}
```

### DNS Timeouts

```go
// Increase timeout
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

// Or use custom resolver with longer timeout
config := &spf.Config{
    DNSResolver: spf.NewDefaultResolver(),
    // ... other config
}
```

### DKIM Signature Not Found

Ensure DKIM-Signature headers are properly parsed:

```go
// DKIM signatures must be in Headers slice
message.Headers = []dkim.Header{
    {Name: "DKIM-Signature", Value: "v=1; a=rsa-sha256; ..."},
    // ... other headers
}
```

## Examples

See the [examples directory](../examples/email_authentication/) for complete working examples including:

- Simple email authentication
- Handling DKIM signatures
- Authentication failure scenarios
- Batch processing
- Custom policy enforcement

## Related Packages

- [`spf`](../) - SPF (RFC 7208) verification
- [`dkim`](../dkim/) - DKIM (RFC 6376) signature verification
- [`dmarc`](../dmarc/) - DMARC (RFC 7489) policy evaluation

## License

See the main project [LICENSE](../LICENSE) file.

## Contributing

Contributions are welcome! Please see the main project [CONTRIBUTING](../CONTRIBUTING.md) guide.
