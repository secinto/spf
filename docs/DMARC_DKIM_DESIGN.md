# DMARC & DKIM Implementation Design Document

**Status:** Design Phase
**Priority:** P0 - Critical
**Owner:** Development Team
**Timeline:** 12 weeks (6 weeks DMARC + 6 weeks DKIM)
**Version:** 1.0

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [DMARC Implementation](#dmarc-implementation)
3. [DKIM Implementation](#dkim-implementation)
4. [Integration Architecture](#integration-architecture)
5. [Testing Strategy](#testing-strategy)
6. [Performance Considerations](#performance-considerations)
7. [Migration Path](#migration-path)

---

## Executive Summary

This document details the technical design for implementing DMARC (RFC 7489) and DKIM (RFC 6376) support in the SPF library, creating a comprehensive email authentication solution.

### Goals
- ✅ RFC-compliant DMARC and DKIM implementations
- ✅ Seamless integration with existing SPF library
- ✅ High performance (<50ms combined auth)
- ✅ Easy-to-use API for developers
- ✅ Backward compatible

### Non-Goals
- ❌ Email client implementation
- ❌ SMTP server implementation
- ❌ Report aggregation service (Phase 2)

---

## DMARC Implementation

### Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    DMARC Package                        │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │   Parser     │  │  Evaluator   │  │   Reporter   │ │
│  │              │  │              │  │  (Optional)  │ │
│  │ - Parse TXT  │  │ - Alignment  │  │ - Generate   │ │
│  │ - Validate   │  │ - Policy     │  │ - Send       │ │
│  │ - Extract    │  │ - Decide     │  │ - Format     │ │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘ │
│         │                 │                 │         │
│         └─────────────────┴─────────────────┘         │
│                           │                           │
│                  ┌────────┴────────┐                  │
│                  │  DNS Resolver   │                  │
│                  │  (Shared)       │                  │
│                  └─────────────────┘                  │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Data Structures

```go
package dmarc

import (
    "net"
    "net/mail"
    "time"
)

// Record represents a parsed DMARC record
type Record struct {
    // Required fields
    Version string  // v=DMARC1

    // Policy fields
    Policy    Policy  // p=none|quarantine|reject
    SubPolicy Policy  // sp=none|quarantine|reject (optional)

    // Alignment
    SPFAlignment  Alignment  // aspf=r|s (default: r)
    DKIMAlignment Alignment  // adkim=r|s (default: r)

    // Sampling
    Percentage int  // pct=0-100 (default: 100)

    // Reporting
    AggregateReportURIs []ReportURI  // rua=mailto:...
    ForensicReportURIs  []ReportURI  // ruf=mailto:...
    ReportFormat        string       // rf=afrf (default)
    ReportInterval      time.Duration // ri=86400 (seconds, default: 86400)

    // Options
    FailureOptions FailureOptions  // fo=0|1|d|s (default: 0)

    // Metadata
    Raw    string    // Original DNS record
    Domain string    // Domain this record applies to
}

type Policy string

const (
    PolicyNone       Policy = "none"
    PolicyQuarantine Policy = "quarantine"
    PolicyReject     Policy = "reject"
)

type Alignment string

const (
    AlignmentRelaxed Alignment = "r"  // Default
    AlignmentStrict  Alignment = "s"
)

type ReportURI struct {
    Scheme string  // mailto or https
    URI    string  // Full URI
    MaxSize int64  // Size limit in bytes (optional)
}

type FailureOptions struct {
    ReportAll              bool  // fo=0 or fo=1
    ReportSPFFailure       bool  // fo=d
    ReportDKIMFailure      bool  // fo=s
    ReportSPFOrDKIMFailure bool  // fo=1
}

// Result represents DMARC evaluation result
type Result struct {
    // Overall result
    Pass bool

    // Component results
    SPFResult      spf.Result
    SPFAligned     bool
    DKIMResults    []DKIMResult
    DKIMAligned    bool

    // Policy decision
    AppliedPolicy  Policy
    Disposition    Disposition

    // Details
    Reason         []string
    Record         *Record

    // RFC 5322.From
    From           string

    // Metadata
    EvaluatedAt    time.Time
}

type Disposition string

const (
    DispositionNone       Disposition = "none"
    DispositionQuarantine Disposition = "quarantine"
    DispositionReject     Disposition = "reject"
)

// Config holds DMARC evaluation configuration
type Config struct {
    // DNS resolver
    Resolver DNSResolver

    // Enable subdomain policy checking
    CheckSubdomains bool

    // Honor percentage sampling
    HonorSampling bool

    // Timeout for DNS lookups
    DNSTimeout time.Duration
}
```

### Core Functions

#### 1. DNS Lookup

```go
// LookupDMARC performs DNS lookup for DMARC record
// Looks up _dmarc.domain TXT record
// Falls back to organizational domain if not found
func LookupDMARC(ctx context.Context, resolver DNSResolver,
                 domain string) (*Record, error) {
    // Try exact domain
    record, err := lookupDMARCRecord(ctx, resolver, domain)
    if err == nil {
        return record, nil
    }

    // Try organizational domain
    orgDomain, err := extractOrganizationalDomain(domain)
    if err != nil {
        return nil, err
    }

    if orgDomain != domain {
        return lookupDMARCRecord(ctx, resolver, orgDomain)
    }

    return nil, ErrNoRecord
}

func lookupDMARCRecord(ctx context.Context, resolver DNSResolver,
                       domain string) (*Record, error) {
    dmarcDomain := "_dmarc." + domain

    records, err := resolver.LookupTXT(ctx, dmarcDomain)
    if err != nil {
        return nil, err
    }

    // Find DMARC record (should be only one)
    var dmarcRecord string
    for _, record := range records {
        if strings.HasPrefix(record, "v=DMARC1") {
            if dmarcRecord != "" {
                return nil, ErrMultipleRecords
            }
            dmarcRecord = record
        }
    }

    if dmarcRecord == "" {
        return nil, ErrNoRecord
    }

    return ParseRecord(dmarcRecord, domain)
}
```

#### 2. Record Parsing

```go
// ParseRecord parses a DMARC TXT record
func ParseRecord(record string, domain string) (*Record, error) {
    r := &Record{
        Raw:           record,
        Domain:        domain,
        SPFAlignment:  AlignmentRelaxed,  // default
        DKIMAlignment: AlignmentRelaxed,  // default
        Percentage:    100,                // default
        ReportInterval: 86400 * time.Second, // default
    }

    // Split into tag=value pairs
    pairs := strings.Split(record, ";")

    for _, pair := range pairs {
        pair = strings.TrimSpace(pair)
        if pair == "" {
            continue
        }

        parts := strings.SplitN(pair, "=", 2)
        if len(parts) != 2 {
            return nil, ErrInvalidTag
        }

        tag := strings.TrimSpace(parts[0])
        value := strings.TrimSpace(parts[1])

        switch tag {
        case "v":
            if value != "DMARC1" {
                return nil, ErrInvalidVersion
            }
            r.Version = value

        case "p":
            policy, err := parsePolicy(value)
            if err != nil {
                return nil, err
            }
            r.Policy = policy

        case "sp":
            policy, err := parsePolicy(value)
            if err != nil {
                return nil, err
            }
            r.SubPolicy = policy

        case "aspf":
            alignment, err := parseAlignment(value)
            if err != nil {
                return nil, err
            }
            r.SPFAlignment = alignment

        case "adkim":
            alignment, err := parseAlignment(value)
            if err != nil {
                return nil, err
            }
            r.DKIMAlignment = alignment

        case "pct":
            pct, err := strconv.Atoi(value)
            if err != nil || pct < 0 || pct > 100 {
                return nil, ErrInvalidPercentage
            }
            r.Percentage = pct

        case "rua":
            uris, err := parseReportURIs(value)
            if err != nil {
                return nil, err
            }
            r.AggregateReportURIs = uris

        case "ruf":
            uris, err := parseReportURIs(value)
            if err != nil {
                return nil, err
            }
            r.ForensicReportURIs = uris

        case "fo":
            options, err := parseFailureOptions(value)
            if err != nil {
                return nil, err
            }
            r.FailureOptions = options

        case "ri":
            seconds, err := strconv.Atoi(value)
            if err != nil || seconds < 0 {
                return nil, ErrInvalidInterval
            }
            r.ReportInterval = time.Duration(seconds) * time.Second

        case "rf":
            r.ReportFormat = value

        // Unknown tags are ignored per RFC 7489
        }
    }

    // Validate required fields
    if r.Version == "" {
        return nil, ErrMissingVersion
    }
    if r.Policy == "" {
        return nil, ErrMissingPolicy
    }

    // Set sub-policy default to policy
    if r.SubPolicy == "" {
        r.SubPolicy = r.Policy
    }

    return r, nil
}

func parsePolicy(value string) (Policy, error) {
    switch value {
    case "none":
        return PolicyNone, nil
    case "quarantine":
        return PolicyQuarantine, nil
    case "reject":
        return PolicyReject, nil
    default:
        return "", ErrInvalidPolicy
    }
}

func parseAlignment(value string) (Alignment, error) {
    switch value {
    case "r":
        return AlignmentRelaxed, nil
    case "s":
        return AlignmentStrict, nil
    default:
        return "", ErrInvalidAlignment
    }
}

func parseReportURIs(value string) ([]ReportURI, error) {
    // Format: mailto:user@domain.com!50m,https://example.com/dmarc
    uris := []ReportURI{}

    parts := strings.Split(value, ",")
    for _, part := range parts {
        part = strings.TrimSpace(part)
        if part == "" {
            continue
        }

        // Extract size limit if present
        var uri string
        var maxSize int64

        if idx := strings.Index(part, "!"); idx != -1 {
            uri = part[:idx]
            sizeStr := part[idx+1:]

            // Parse size (e.g., "50m", "10k", "1g")
            maxSize = parseSizeLimit(sizeStr)
        } else {
            uri = part
        }

        uris = append(uris, ReportURI{
            URI:     uri,
            MaxSize: maxSize,
        })
    }

    return uris, nil
}

func parseFailureOptions(value string) (FailureOptions, error) {
    opts := FailureOptions{}

    parts := strings.Split(value, ":")
    for _, part := range parts {
        switch part {
        case "0":
            opts.ReportAll = true
        case "1":
            opts.ReportSPFOrDKIMFailure = true
        case "d":
            opts.ReportDKIMFailure = true
        case "s":
            opts.ReportSPFFailure = true
        default:
            return opts, ErrInvalidFailureOption
        }
    }

    return opts, nil
}
```

#### 3. Alignment Checking

```go
// CheckSPFAlignment determines if SPF identifier is aligned
func CheckSPFAlignment(mailFromDomain, headerFromDomain string,
                       mode Alignment) bool {
    if mode == AlignmentStrict {
        // Strict: exact match required
        return strings.EqualFold(mailFromDomain, headerFromDomain)
    }

    // Relaxed: organizational domain match
    mailFromOrg := extractOrganizationalDomain(mailFromDomain)
    headerFromOrg := extractOrganizationalDomain(headerFromDomain)

    return strings.EqualFold(mailFromOrg, headerFromOrg)
}

// CheckDKIMAlignment determines if DKIM signature is aligned
func CheckDKIMAlignment(dkimDomain, headerFromDomain string,
                        mode Alignment) bool {
    if mode == AlignmentStrict {
        // Strict: exact match required
        return strings.EqualFold(dkimDomain, headerFromDomain)
    }

    // Relaxed: organizational domain match
    dkimOrg := extractOrganizationalDomain(dkimDomain)
    headerFromOrg := extractOrganizationalDomain(headerFromDomain)

    return strings.EqualFold(dkimOrg, headerFromOrg)
}

// extractOrganizationalDomain extracts the organizational domain
// from a fully qualified domain name using the Public Suffix List
func extractOrganizationalDomain(domain string) string {
    // Use publicsuffix library
    // golang.org/x/net/publicsuffix

    etld, err := publicsuffix.PublicSuffix(domain)
    if err != nil {
        return domain
    }

    // Find the organizational domain (one label above public suffix)
    labels := strings.Split(domain, ".")
    etldLabels := strings.Split(etld, ".")

    if len(labels) <= len(etldLabels) {
        return domain
    }

    // Get one label before public suffix
    orgLabels := labels[len(labels)-len(etldLabels)-1:]
    return strings.Join(orgLabels, ".")
}
```

#### 4. Policy Evaluation

```go
// Evaluate performs DMARC policy evaluation
func Evaluate(ctx context.Context, config *Config, message *Message,
              spfResult spf.Result, dkimResults []DKIMResult) (*Result, error) {

    result := &Result{
        SPFResult:   spfResult,
        DKIMResults: dkimResults,
        EvaluatedAt: time.Now(),
    }

    // Extract RFC 5322.From domain
    from, err := mail.ParseAddress(message.From)
    if err != nil {
        return nil, err
    }
    parts := strings.Split(from.Address, "@")
    if len(parts) != 2 {
        return nil, ErrInvalidFrom
    }
    fromDomain := parts[1]
    result.From = from.Address

    // Lookup DMARC record
    record, err := LookupDMARC(ctx, config.Resolver, fromDomain)
    if err != nil {
        if err == ErrNoRecord {
            // No DMARC record = no policy
            result.Pass = false
            result.AppliedPolicy = PolicyNone
            result.Disposition = DispositionNone
            return result, nil
        }
        return nil, err
    }
    result.Record = record

    // Check SPF alignment
    if spfResult == spf.Pass {
        result.SPFAligned = CheckSPFAlignment(
            message.MailFrom,
            fromDomain,
            record.SPFAlignment,
        )
    }

    // Check DKIM alignment
    for _, dkimResult := range dkimResults {
        if dkimResult.Valid {
            if CheckDKIMAlignment(dkimResult.Domain, fromDomain,
                                 record.DKIMAlignment) {
                result.DKIMAligned = true
                break
            }
        }
    }

    // Determine pass/fail
    // DMARC passes if either SPF or DKIM is aligned
    result.Pass = result.SPFAligned || result.DKIMAligned

    // Determine policy to apply
    policy := record.Policy
    if isSubdomain(fromDomain, record.Domain) {
        policy = record.SubPolicy
    }
    result.AppliedPolicy = policy

    // Apply sampling
    if config.HonorSampling {
        if shouldSample(record.Percentage) {
            result.Disposition = policyToDisposition(policy)
        } else {
            result.Disposition = DispositionNone
            result.Reason = append(result.Reason, "sampled out")
        }
    } else {
        result.Disposition = policyToDisposition(policy)
    }

    // If DMARC passes, override disposition
    if result.Pass {
        result.Disposition = DispositionNone
    }

    return result, nil
}

func policyToDisposition(policy Policy) Disposition {
    switch policy {
    case PolicyNone:
        return DispositionNone
    case PolicyQuarantine:
        return DispositionQuarantine
    case PolicyReject:
        return DispositionReject
    default:
        return DispositionNone
    }
}

func shouldSample(percentage int) bool {
    // Use cryptographically secure random number
    return rand.Intn(100) < percentage
}

func isSubdomain(domain, parentDomain string) bool {
    if domain == parentDomain {
        return false
    }
    return strings.HasSuffix(domain, "."+parentDomain)
}
```

### Error Types

```go
var (
    ErrNoRecord          = errors.New("no DMARC record found")
    ErrMultipleRecords   = errors.New("multiple DMARC records found")
    ErrInvalidVersion    = errors.New("invalid DMARC version")
    ErrInvalidPolicy     = errors.New("invalid policy value")
    ErrInvalidAlignment  = errors.New("invalid alignment mode")
    ErrInvalidPercentage = errors.New("invalid percentage value")
    ErrInvalidInterval   = errors.New("invalid report interval")
    ErrInvalidFailureOption = errors.New("invalid failure reporting option")
    ErrMissingVersion    = errors.New("missing required version tag")
    ErrMissingPolicy     = errors.New("missing required policy tag")
    ErrInvalidTag        = errors.New("invalid tag format")
    ErrInvalidFrom       = errors.New("invalid From header")
)
```

---

## DKIM Implementation

### Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    DKIM Package                         │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │   Parser     │  │   Verifier   │  │    Signer    │ │
│  │              │  │              │  │  (Optional)  │ │
│  │ - Parse sig  │  │ - Fetch key  │  │ - Generate   │ │
│  │ - Extract    │  │ - Canonize   │  │ - Sign       │ │
│  │ - Validate   │  │ - Verify     │  │ - Format     │ │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘ │
│         │                 │                 │         │
│         └─────────────────┴─────────────────┘         │
│                           │                           │
│         ┌─────────────────┴─────────────────┐         │
│         │                                   │         │
│  ┌──────┴────────┐              ┌──────────┴───────┐ │
│  │ Canonicalizer │              │   DNS Resolver   │ │
│  │ - Simple      │              │   (Shared)       │ │
│  │ - Relaxed     │              └──────────────────┘ │
│  └───────────────┘                                   │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Data Structures

```go
package dkim

import (
    "crypto"
    "crypto/rsa"
    "time"
)

// Signature represents a parsed DKIM-Signature header
type Signature struct {
    // Required tags
    Version        string      // v=1
    Algorithm      Algorithm   // a=rsa-sha256
    Signature      []byte      // b=base64...
    BodyHash       []byte      // bh=base64...
    Domain         string      // d=example.com
    Selector       string      // s=default
    Headers        []string    // h=from:to:subject:date

    // Canonicalization
    HeaderCanon CanonMode      // c=relaxed/simple (header)
    BodyCanon   CanonMode      // c=relaxed/simple (body)

    // Optional tags
    BodyLength     int         // l=1234 (dangerous, avoid)
    QueryMethod    string      // q=dns/txt
    Identity       string      // i=user@example.com
    Timestamp      time.Time   // t=1234567890
    Expiration     time.Time   // x=1234567890
    CopiedHeaders  map[string]string  // z=header:value|header:value

    // Metadata
    Raw string  // Original header value
}

type Algorithm string

const (
    AlgorithmRSASHA1   Algorithm = "rsa-sha1"   // Deprecated
    AlgorithmRSASHA256 Algorithm = "rsa-sha256" // Recommended
    AlgorithmED25519   Algorithm = "ed25519-sha256" // Optional
)

type CanonMode string

const (
    CanonSimple  CanonMode = "simple"
    CanonRelaxed CanonMode = "relaxed"
)

// PublicKey represents a DKIM public key from DNS
type PublicKey struct {
    Version    string      // v=DKIM1
    KeyType    KeyType     // k=rsa or k=ed25519
    PublicKey  interface{} // *rsa.PublicKey or ed25519.PublicKey
    Services   []string    // s=email:* (default: *)
    Flags      Flags       // t=y:s
    Notes      string      // n=notes

    // Metadata
    Raw      string
    Domain   string
    Selector string
}

type KeyType string

const (
    KeyTypeRSA     KeyType = "rsa"
    KeyTypeED25519 KeyType = "ed25519"
)

type Flags struct {
    Testing     bool  // t=y
    StrictDomain bool  // t=s
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

// Message represents an email message for DKIM operations
type Message struct {
    Headers []Header
    Body    []byte
}

type Header struct {
    Name  string
    Value string
}
```

### Core Functions

#### 1. Signature Parsing

```go
// ParseSignature parses a DKIM-Signature header
func ParseSignature(header string) (*Signature, error) {
    sig := &Signature{
        Raw:         header,
        HeaderCanon: CanonSimple,  // default
        BodyCanon:   CanonSimple,  // default
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
            b, err := base64.StdEncoding.DecodeString(value)
            if err != nil {
                return nil, ErrInvalidSignature
            }
            sig.Signature = b

        case "bh":
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

func parseTagValueList(input string) map[string]string {
    tags := make(map[string]string)

    // Remove folding whitespace (FWS)
    input = strings.ReplaceAll(input, "\r\n", "")
    input = strings.ReplaceAll(input, "\n", "")
    input = strings.ReplaceAll(input, "\t", " ")

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
```

#### 2. Public Key Retrieval

```go
// LookupPublicKey retrieves DKIM public key from DNS
func LookupPublicKey(ctx context.Context, resolver DNSResolver,
                     selector, domain string) (*PublicKey, error) {

    // Construct DNS query: selector._domainkey.domain
    dkimDomain := fmt.Sprintf("%s._domainkey.%s", selector, domain)

    records, err := resolver.LookupTXT(ctx, dkimDomain)
    if err != nil {
        return nil, ErrKeyNotFound
    }

    // Concatenate multi-string TXT record
    var record string
    for _, r := range records {
        record += r
    }

    return ParsePublicKey(record, selector, domain)
}

// ParsePublicKey parses a DKIM public key TXT record
func ParsePublicKey(record, selector, domain string) (*PublicKey, error) {
    key := &PublicKey{
        Raw:      record,
        Selector: selector,
        Domain:   domain,
        KeyType:  KeyTypeRSA,  // default
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

            pubKey, err := parsePublicKeyData(value, key.KeyType)
            if err != nil {
                return nil, err
            }
            key.PublicKey = pubKey

        case "s":
            key.Services = strings.Split(value, ":")

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
```

#### 3. Canonicalization

```go
// CanonicalizeHeaders applies header canonicalization
func CanonicalizeHeaders(headers []Header, mode CanonMode,
                         signedHeaders []string) []byte {
    var buf bytes.Buffer

    // Build map of headers to sign
    headerMap := make(map[string][]string)
    for _, h := range headers {
        name := strings.ToLower(h.Name)
        headerMap[name] = append(headerMap[name], h.Value)
    }

    // Process headers in order specified by h= tag
    for _, name := range signedHeaders {
        name = strings.ToLower(name)
        values, exists := headerMap[name]
        if !exists {
            continue
        }

        // Use most recent occurrence
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

    return buf.Bytes()
}

func canonicalizeHeaderName(name string) string {
    return strings.ToLower(strings.TrimSpace(name))
}

func canonicalizeHeaderValue(value string) string {
    // Convert all whitespace sequences to single space
    // Remove leading/trailing whitespace
    value = strings.TrimSpace(value)
    value = regexp.MustCompile(`\s+`).ReplaceAllString(value, " ")
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
    // Convert line endings to CRLF
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
    // Convert to lines
    lines := bytes.Split(body, []byte("\n"))

    var result []byte
    for _, line := range lines {
        // Remove trailing whitespace
        line = bytes.TrimRight(line, " \t\r")

        // Reduce whitespace sequences to single space
        line = regexp.MustCompile(`[ \t]+`).ReplaceAll(line, []byte(" "))

        result = append(result, line...)
        result = append(result, []byte("\r\n")...)
    }

    // Remove trailing empty lines
    for bytes.HasSuffix(result, []byte("\r\n\r\n")) {
        result = result[:len(result)-2]
    }

    return result
}

// ComputeBodyHash computes body hash
func ComputeBodyHash(body []byte, canon CanonMode, length int) []byte {
    // Canonicalize body
    canonBody := CanonicalizeBody(body, canon)

    // Truncate if length specified
    if length > 0 && length < len(canonBody) {
        canonBody = canonBody[:length]
    }

    // Compute SHA-256 hash
    hash := sha256.Sum256(canonBody)
    return hash[:]
}
```

#### 4. Signature Verification

```go
// Verify verifies a DKIM signature
func Verify(ctx context.Context, resolver DNSResolver,
            message *Message, signature *Signature) (*Result, error) {

    result := &Result{
        Domain:        signature.Domain,
        Selector:      signature.Selector,
        Algorithm:     signature.Algorithm,
        SignatureTime: signature.Timestamp,
    }

    // 1. Fetch public key
    pubKey, err := LookupPublicKey(ctx, resolver,
                                   signature.Selector,
                                   signature.Domain)
    if err != nil {
        result.Error = err
        return result, nil
    }

    // 2. Verify body hash
    bodyHash := ComputeBodyHash(message.Body, signature.BodyCanon,
                                signature.BodyLength)

    if !bytes.Equal(bodyHash, signature.BodyHash) {
        result.Error = ErrBodyHashMismatch
        result.BodyOK = false
        return result, nil
    }
    result.BodyOK = true

    // 3. Canonicalize headers
    canonHeaders := CanonicalizeHeaders(message.Headers,
                                       signature.HeaderCanon,
                                       signature.Headers)

    // 4. Add DKIM-Signature header (with b= empty)
    dkimHeader := constructDKIMHeader(signature, "")
    canonHeaders = append(canonHeaders, dkimHeader...)

    // 5. Verify signature
    valid, err := verifySignature(canonHeaders, signature.Signature,
                                  pubKey.PublicKey, signature.Algorithm)
    if err != nil {
        result.Error = err
        return result, nil
    }

    result.Valid = valid
    result.HeadersOK = valid

    return result, nil
}

func verifySignature(data, signature []byte, pubKey interface{},
                     algo Algorithm) (bool, error) {

    switch algo {
    case AlgorithmRSASHA256:
        rsaKey, ok := pubKey.(*rsa.PublicKey)
        if !ok {
            return false, ErrInvalidKeyType
        }

        hash := sha256.Sum256(data)
        err := rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256,
                                  hash[:], signature)
        return err == nil, err

    case AlgorithmED25519:
        ed25519Key, ok := pubKey.(ed25519.PublicKey)
        if !ok {
            return false, ErrInvalidKeyType
        }

        return ed25519.Verify(ed25519Key, data, signature), nil

    default:
        return false, ErrUnsupportedAlgorithm
    }
}
```

---

## Integration Architecture

### Combined Authentication Flow

```go
package emailauth

import (
    "github.com/asggo/spf"
    "github.com/asggo/spf/dkim"
    "github.com/asggo/spf/dmarc"
)

// AuthResult combines SPF, DKIM, and DMARC results
type AuthResult struct {
    SPF   spf.Result
    DKIM  []dkim.Result
    DMARC dmarc.Result

    Pass  bool  // Overall authentication pass
    Score int   // Composite score 0-100
}

// Authenticate performs complete email authentication
func Authenticate(ctx context.Context, config *Config,
                  message *Message) (*AuthResult, error) {

    result := &AuthResult{}

    // 1. SPF Check
    spfResult, err := spf.SPFTestContext(ctx, config.SPFConfig,
                                        message.ClientIP,
                                        message.MailFrom)
    if err != nil {
        return nil, err
    }
    result.SPF = spfResult

    // 2. DKIM Verification
    dkimResults, err := dkim.VerifyMessage(ctx, config.Resolver,
                                          message.Raw)
    if err != nil {
        return nil, err
    }
    result.DKIM = dkimResults

    // 3. DMARC Evaluation
    dmarcResult, err := dmarc.Evaluate(ctx, config.DMARCConfig,
                                      message, spfResult, dkimResults)
    if err != nil {
        return nil, err
    }
    result.DMARC = dmarcResult

    // 4. Compute composite result
    result.Pass = dmarcResult.Pass
    result.Score = computeAuthScore(result)

    return result, nil
}

func computeAuthScore(result *AuthResult) int {
    score := 0

    // SPF contribution (0-30 points)
    switch result.SPF {
    case spf.Pass:
        score += 30
    case spf.SoftFail:
        score += 15
    case spf.Neutral:
        score += 10
    }

    // DKIM contribution (0-40 points)
    validDKIM := 0
    for _, dkim := range result.DKIM {
        if dkim.Valid {
            validDKIM++
        }
    }
    if validDKIM > 0 {
        score += 40
    } else if len(result.DKIM) > 0 {
        score += 10
    }

    // DMARC contribution (0-30 points)
    if result.DMARC.Pass {
        score += 30
    } else if result.DMARC.SPFAligned || result.DMARC.DKIMAligned {
        score += 15
    }

    return score
}
```

---

## Testing Strategy

### Unit Tests

```go
// DMARC Parser Tests
func TestParseDMARCRecord(t *testing.T) {
    tests := []struct {
        name    string
        record  string
        want    *dmarc.Record
        wantErr bool
    }{
        {
            name:   "basic record",
            record: "v=DMARC1; p=none",
            want: &dmarc.Record{
                Version: "DMARC1",
                Policy:  dmarc.PolicyNone,
            },
        },
        // ... more test cases
    }
}

// DKIM Verification Tests
func TestDKIMVerify(t *testing.T) {
    // Test with known good signatures
    // Test with expired signatures
    // Test with invalid signatures
    // Test with revoked keys
}
```

### Integration Tests

```go
func TestFullAuthentication(t *testing.T) {
    // Test complete authentication flow
    // with mock DNS resolver

    resolver := &MockResolver{
        // Setup test data
    }

    message := &emailauth.Message{
        // Test message
    }

    result, err := emailauth.Authenticate(ctx, config, message)
    // Assertions
}
```

### RFC Compliance Tests

- Test against RFC 7489 DMARC examples
- Test against RFC 6376 DKIM examples
- Test with real emails from major providers

---

## Performance Considerations

### Benchmarks

```go
func BenchmarkDMARCLookup(b *testing.B)
func BenchmarkDMARCEvaluate(b *testing.B)
func BenchmarkDKIMVerify(b *testing.B)
func BenchmarkFullAuth(b *testing.B)
```

### Performance Targets

- **DMARC Lookup:** <5ms
- **DMARC Evaluation:** <2ms
- **DKIM Verification:** <20ms (RSA-2048)
- **Combined Auth:** <50ms total

### Optimizations

1. **DNS Caching** - Cache DMARC/DKIM records
2. **Key Caching** - Cache parsed public keys
3. **Parallel Operations** - Run SPF/DKIM in parallel
4. **Lazy Evaluation** - Skip DKIM if SPF+DMARC sufficient

---

## Migration Path

### Phase 1: Foundation (Weeks 1-2)
- Create package structure
- Implement basic types
- Setup testing framework

### Phase 2: DMARC Core (Weeks 3-6)
- DNS lookup
- Parser
- Alignment checking
- Policy evaluation

### Phase 3: DKIM Core (Weeks 7-12)
- Signature parsing
- Key retrieval
- Canonicalization
- Verification

### Phase 4: Integration (Week 13)
- Combined authentication
- Documentation
- Examples

### Phase 5: Polish (Week 14)
- Performance tuning
- Additional tests
- Release preparation

---

## Dependencies

```go
// Required
"crypto/rsa"
"crypto/sha256"
"crypto/x509"
"encoding/base64"
"net"
"net/mail"
"time"

// Recommended
"golang.org/x/net/publicsuffix"  // Organizational domain
"crypto/ed25519"                  // ED25519 support (optional)
```

---

## References

- [RFC 7489 - DMARC](https://tools.ietf.org/html/rfc7489)
- [RFC 6376 - DKIM](https://tools.ietf.org/html/rfc6376)
- [RFC 5322 - Internet Message Format](https://tools.ietf.org/html/rfc5322)
- [Public Suffix List](https://publicsuffix.org/)

---

**Document Status:** Final Draft
**Last Updated:** 2025-01-10
**Next Review:** 2025-02-10
