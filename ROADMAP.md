# SPF Library Roadmap

This document outlines the planned feature enhancements for the SPF library, organized by priority and implementation complexity.

## Table of Contents
- [Phase 1: Email Authentication Suite (DMARC & DKIM)](#phase-1-email-authentication-suite-dmarc--dkim)
- [Phase 2: Infrastructure & Performance](#phase-2-infrastructure--performance)
- [Phase 3: Observability & Operations](#phase-3-observability--operations)
- [Phase 4: Developer Tools & Services](#phase-4-developer-tools--services)
- [Phase 5: Advanced Features](#phase-5-advanced-features)

---

## Phase 1: Email Authentication Suite (DMARC & DKIM)

**Priority:** P0 - Critical
**Timeline:** 4-6 weeks
**Dependencies:** Current SPF implementation
**Status:** Planned

### 1.1 DMARC Integration

#### Overview
Implement RFC 7489 (Domain-based Message Authentication, Reporting, and Conformance) to provide a complete email authentication solution alongside SPF.

#### Features

##### 1.1.1 DMARC Record Parsing
```go
type DMARCRecord struct {
    Version     string           // v=DMARC1
    Policy      DMARCPolicy      // none, quarantine, reject
    SubPolicy   DMARCPolicy      // Subdomain policy
    Percentage  int              // pct=100
    RUA         []string         // Aggregate report URIs
    RUF         []string         // Forensic report URIs
    ASPF        AlignmentMode    // SPF alignment (r=relaxed, s=strict)
    ADKIM       AlignmentMode    // DKIM alignment
    Interval    time.Duration    // ri=86400
    Options     DMARCOptions     // fo=0:1:d:s
}

type DMARCPolicy string
const (
    PolicyNone       DMARCPolicy = "none"
    PolicyQuarantine DMARCPolicy = "quarantine"
    PolicyReject     DMARCPolicy = "reject"
)

type AlignmentMode string
const (
    AlignmentRelaxed AlignmentMode = "r"
    AlignmentStrict  AlignmentMode = "s"
)
```

##### 1.1.2 DMARC Policy Evaluation
```go
// DMARCResult represents the outcome of DMARC validation
type DMARCResult struct {
    Pass          bool
    SPFAligned    bool
    DKIMAligned   bool
    Policy        DMARCPolicy
    Disposition   string        // none, quarantine, reject
    Reason        []string      // Failure reasons
    SPFResult     Result        // Underlying SPF result
    DKIMResult    DKIMResult    // Underlying DKIM result
}

// EvaluateDMARC performs DMARC policy evaluation
func EvaluateDMARC(ctx context.Context, config *Config,
                   domain, fromDomain string,
                   spfResult Result,
                   dkimResults []DKIMResult) (DMARCResult, error)
```

##### 1.1.3 Alignment Checking
```go
// CheckSPFAlignment verifies SPF identifier alignment
func CheckSPFAlignment(mailFromDomain, headerFromDomain string,
                       mode AlignmentMode) bool

// CheckDKIMAlignment verifies DKIM signature alignment
func CheckDKIMAlignment(dkimDomain, headerFromDomain string,
                        mode AlignmentMode) bool
```

##### 1.1.4 Aggregate Reporting (Optional)
```go
type DMARCReport struct {
    OrgName       string
    ReportID      string
    DateRange     DateRange
    Records       []DMARCReportRecord
}

type DMARCReportRecord struct {
    SourceIP      string
    Count         int
    Disposition   string
    SPFResult     string
    DKIMResult    string
    HeaderFrom    string
}

// GenerateDMARCReport creates an aggregate report
func GenerateDMARCReport(records []DMARCReportRecord,
                         period DateRange) ([]byte, error)
```

#### Implementation Steps

1. **Week 1-2: DMARC Record Parser**
   - Implement `ParseDMARCRecord(record string) (DMARCRecord, error)`
   - Add DNS lookup for `_dmarc.domain.com`
   - Validate all DMARC tags (v, p, sp, pct, rua, ruf, aspf, adkim, ri, fo)
   - Handle organizational domain extraction
   - Write comprehensive tests

2. **Week 3-4: Policy Evaluation Engine**
   - Implement alignment checking (relaxed and strict)
   - Build policy decision logic
   - Handle percentage-based sampling
   - Integrate with existing SPF results
   - Add DKIM result integration points

3. **Week 5: Testing & Documentation**
   - Test against real-world DMARC records
   - Benchmark performance
   - Write usage examples
   - Update documentation

4. **Week 6: Optional Reporting**
   - Implement aggregate report generation
   - Add report formatting (XML)
   - Add report submission helpers

#### API Design

```go
package dmarc

// Public API
func LookupDMARC(ctx context.Context, resolver DNSResolver,
                 domain string) (*DMARCRecord, error)

func ParseDMARC(record string) (*DMARCRecord, error)

func EvaluatePolicy(ctx context.Context, config *DMARCConfig,
                    message *EmailMessage) (*DMARCResult, error)

// Usage Example
func main() {
    ctx := context.Background()
    resolver := spf.NewDefaultResolver()

    // Lookup DMARC record
    dmarcRecord, err := dmarc.LookupDMARC(ctx, resolver, "example.com")
    if err != nil {
        log.Fatal(err)
    }

    // Evaluate policy
    result, err := dmarc.EvaluatePolicy(ctx, nil, message)
    if err != nil {
        log.Fatal(err)
    }

    switch {
    case result.Pass:
        // Accept message
    case result.Policy == dmarc.PolicyReject:
        // Reject message
    case result.Policy == dmarc.PolicyQuarantine:
        // Quarantine message
    }
}
```

#### Testing Strategy

- **Unit Tests:** All parsing and validation functions
- **Integration Tests:** Real DMARC records from major domains
- **Edge Cases:** Malformed records, missing tags, organizational domains
- **Performance:** Benchmark DMARC lookups and evaluation

---

### 1.2 DKIM Support

#### Overview
Implement RFC 6376 (DomainKeys Identified Mail) to verify email message signatures and enable multi-factor authentication.

#### Features

##### 1.2.1 DKIM Signature Parsing
```go
type DKIMSignature struct {
    Version        string      // v=1
    Algorithm      string      // a=rsa-sha256
    Domain         string      // d=example.com
    Selector       string      // s=default
    Headers        []string    // h=from:to:subject:date
    BodyHash       string      // bh=base64...
    Signature      string      // b=base64...
    Canonicalization Canonicalization // c=relaxed/simple
    BodyLength     int         // l=1234
    QueryMethod    string      // q=dns/txt
    Timestamp      time.Time   // t=1234567890
    Expiration     time.Time   // x=1234567890
    Identity       string      // i=user@example.com
    CopiedHeaders  []string    // z=header:value|header:value
}

type Canonicalization struct {
    Header CanonMode
    Body   CanonMode
}

type CanonMode string
const (
    CanonSimple  CanonMode = "simple"
    CanonRelaxed CanonMode = "relaxed"
)
```

##### 1.2.2 DKIM Verification
```go
type DKIMResult struct {
    Valid         bool
    Domain        string
    Selector      string
    Error         error
    Algorithm     string
    SignatureTime time.Time
}

// VerifyDKIM verifies a DKIM signature
func VerifyDKIM(ctx context.Context, resolver DNSResolver,
                message []byte, signature *DKIMSignature) (DKIMResult, error)

// VerifyAllDKIM verifies all DKIM signatures in an email
func VerifyAllDKIM(ctx context.Context, resolver DNSResolver,
                   message []byte) ([]DKIMResult, error)
```

##### 1.2.3 Public Key Retrieval
```go
type DKIMPublicKey struct {
    Version    string      // v=DKIM1
    KeyType    string      // k=rsa
    PublicKey  []byte      // p=base64...
    Services   []string    // s=email:*
    Flags      []string    // t=s:y
    Notes      string      // n=notes
}

// LookupDKIMKey retrieves DKIM public key from DNS
func LookupDKIMKey(ctx context.Context, resolver DNSResolver,
                   selector, domain string) (*DKIMPublicKey, error)
```

##### 1.2.4 Message Canonicalization
```go
// CanonicalizeHeader applies header canonicalization
func CanonicalizeHeader(headers []byte, mode CanonMode) []byte

// CanonicalizeBody applies body canonicalization
func CanonicalizeBody(body []byte, mode CanonMode) []byte

// ComputeBodyHash computes the body hash
func ComputeBodyHash(body []byte, canon CanonMode,
                     length int) string
```

##### 1.2.5 Signature Generation (Optional)
```go
type DKIMSigner struct {
    Domain     string
    Selector   string
    PrivateKey interface{}
    Headers    []string
    Canon      Canonicalization
}

// Sign creates a DKIM signature for a message
func (s *DKIMSigner) Sign(message []byte) (string, error)
```

#### Implementation Steps

1. **Week 1: DKIM Signature Parsing**
   - Implement `ParseDKIMSignature(header string) (*DKIMSignature, error)`
   - Parse all DKIM tags (v, a, d, s, h, bh, b, c, l, q, t, x, i, z)
   - Validate signature format
   - Handle multiple signatures
   - Write parser tests

2. **Week 2: DNS Key Retrieval**
   - Implement `LookupDKIMKey(selector, domain)`
   - Parse DKIM public key records
   - Handle key types (RSA, ED25519)
   - Add caching support
   - Test with real keys

3. **Week 3: Message Canonicalization**
   - Implement simple canonicalization
   - Implement relaxed canonicalization
   - Handle header selection
   - Compute body hashes
   - Test against RFC examples

4. **Week 4: Signature Verification**
   - Implement RSA signature verification
   - Implement ED25519 verification (optional)
   - Verify header hash
   - Verify body hash
   - Check expiration and timestamps

5. **Week 5: Integration & Testing**
   - Test with real emails
   - Benchmark verification performance
   - Add comprehensive test suite
   - Test against major email providers

6. **Week 6: Optional Signing**
   - Implement signature generation
   - Add private key handling
   - Create signing examples
   - Document signing process

#### API Design

```go
package dkim

// Public API
func ParseSignatures(message []byte) ([]*DKIMSignature, error)

func VerifyMessage(ctx context.Context, resolver DNSResolver,
                   message []byte) ([]DKIMResult, error)

func VerifySignature(ctx context.Context, resolver DNSResolver,
                     message []byte, sig *DKIMSignature) (DKIMResult, error)

// Usage Example
func main() {
    ctx := context.Background()
    resolver := spf.NewDefaultResolver()

    // Read email message
    message, _ := ioutil.ReadFile("email.eml")

    // Verify all DKIM signatures
    results, err := dkim.VerifyMessage(ctx, resolver, message)
    if err != nil {
        log.Fatal(err)
    }

    // Check results
    for _, result := range results {
        if result.Valid {
            fmt.Printf("Valid signature from %s\n", result.Domain)
        } else {
            fmt.Printf("Invalid signature: %v\n", result.Error)
        }
    }
}
```

#### Testing Strategy

- **Unit Tests:** Parser, canonicalization, hash computation
- **Integration Tests:** Full verification with test messages
- **RFC Compliance:** Test against RFC 6376 examples
- **Real-world:** Test with emails from Gmail, Outlook, etc.
- **Performance:** Benchmark signature verification

#### Cryptography Libraries

```go
// Dependencies
import (
    "crypto/rsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/base64"
    "encoding/pem"
)

// For ED25519 (optional)
import "crypto/ed25519"
```

---

### 1.3 Combined Email Authentication

#### Multi-Factor Authentication
```go
type EmailAuthResult struct {
    SPF   Result
    DKIM  []DKIMResult
    DMARC DMARCResult
    Score int              // Composite score 0-100
    Pass  bool             // Overall pass/fail
}

// AuthenticateEmail performs comprehensive email authentication
func AuthenticateEmail(ctx context.Context, config *AuthConfig,
                       message *EmailMessage) (*EmailAuthResult, error)
```

#### Usage Example
```go
func main() {
    ctx := context.Background()
    config := &AuthConfig{
        SPFConfig:   spf.DefaultConfig(),
        CheckDKIM:   true,
        CheckDMARC:  true,
    }

    result, err := AuthenticateEmail(ctx, config, message)
    if err != nil {
        log.Fatal(err)
    }

    if result.Pass && result.Score >= 80 {
        // Accept email
    } else if result.Score >= 50 {
        // Quarantine
    } else {
        // Reject
    }
}
```

---

## Phase 2: Infrastructure & Performance

### 2.1 DNS-over-HTTPS (DoH)

**Priority:** P1 - High
**Timeline:** 2-3 weeks

```go
type DoHResolver struct {
    endpoint string
    client   *http.Client
}

func NewDoHResolver(endpoint string) *DoHResolver
func (r *DoHResolver) LookupTXT(ctx context.Context, domain string) ([]string, error)
```

**Providers:**
- Cloudflare: `https://cloudflare-dns.com/dns-query`
- Google: `https://dns.google/resolve`
- Quad9: `https://dns.quad9.net/dns-query`

### 2.2 Advanced Caching

**Priority:** P1 - High
**Timeline:** 2 weeks

**Features:**
- LRU cache with size limits
- Redis backend support
- Memcached backend support
- TTL-aware caching from DNS records
- Cache warming/preloading

```go
type CacheBackend interface {
    Get(key string) (interface{}, error)
    Set(key string, value interface{}, ttl time.Duration) error
    Delete(key string) error
}

type RedisCacheBackend struct {
    client *redis.Client
}

type LRUCache struct {
    maxSize int
    cache   *lru.Cache
}
```

### 2.3 Rate Limiting

**Priority:** P2 - Medium
**Timeline:** 1-2 weeks

**Features:**
- Token bucket algorithm
- Per-domain rate limits
- Per-IP rate limits
- Configurable burst sizes

```go
type RateLimiter struct {
    limits map[string]*TokenBucket
}

type TokenBucket struct {
    capacity  int
    tokens    int
    refillRate time.Duration
}

func (r *RateLimiter) Allow(key string) bool
func (r *RateLimiter) SetLimit(key string, rate int, burst int)
```

---

## Phase 3: Observability & Operations

### 3.1 Metrics & Monitoring

**Priority:** P1 - High
**Timeline:** 2 weeks

**Prometheus Metrics:**
```go
var (
    spfChecksTotal = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "spf_checks_total",
            Help: "Total number of SPF checks",
        },
        []string{"result"},
    )

    spfCheckDuration = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "spf_check_duration_seconds",
            Help: "SPF check duration in seconds",
        },
        []string{"mechanism"},
    )

    dnsLookupsTotal = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "dns_lookups_total",
            Help: "Total number of DNS lookups",
        },
        []string{"type", "status"},
    )

    cacheHitsTotal = prometheus.NewCounter(
        prometheus.CounterOpts{
            Name: "cache_hits_total",
            Help: "Total number of cache hits",
        },
    )
)
```

### 3.2 OpenTelemetry Tracing

**Priority:** P2 - Medium
**Timeline:** 1 week

```go
import "go.opentelemetry.io/otel"

func SPFTestWithTracing(ctx context.Context, ip, email string) (Result, error) {
    ctx, span := otel.Tracer("spf").Start(ctx, "SPFTest")
    defer span.End()

    span.SetAttributes(
        attribute.String("ip", ip),
        attribute.String("email", email),
    )

    // ... SPF checking logic

    span.SetAttributes(attribute.String("result", string(result)))
    return result, err
}
```

### 3.3 Structured Logging

**Priority:** P2 - Medium
**Timeline:** 1 week

```go
type Logger interface {
    Debug(msg string, fields ...Field)
    Info(msg string, fields ...Field)
    Warn(msg string, fields ...Field)
    Error(msg string, fields ...Field)
}

type Field struct {
    Key   string
    Value interface{}
}

// Use with popular logging libraries
import "go.uber.org/zap"
import "github.com/sirupsen/logrus"
```

---

## Phase 4: Developer Tools & Services

### 4.1 SPF Validation CLI

**Priority:** P2 - Medium
**Timeline:** 1 week

```bash
# Install
go install github.com/asggo/spf/cmd/spfcheck@latest

# Usage
spfcheck validate example.com
spfcheck test 192.0.2.1 sender@example.com
spfcheck generate --ip 192.0.2.0/24 --include _spf.google.com
```

**Features:**
- Validate SPF records
- Test IP/email combinations
- Generate SPF records
- Explain SPF results
- Check for common issues

### 4.2 REST API Service

**Priority:** P2 - Medium
**Timeline:** 2 weeks

```go
// API Endpoints
POST /api/v1/spf/check
GET  /api/v1/spf/validate/{domain}
GET  /api/v1/dmarc/{domain}
GET  /api/v1/dkim/verify
```

**Example:**
```bash
curl -X POST http://localhost:8080/api/v1/spf/check \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.0.2.1", "email": "sender@example.com"}'
```

### 4.3 gRPC Service

**Priority:** P3 - Low
**Timeline:** 2 weeks

```protobuf
service SPFService {
  rpc CheckSPF(SPFRequest) returns (SPFResponse);
  rpc ValidateRecord(ValidateRequest) returns (ValidateResponse);
  rpc StreamChecks(stream SPFRequest) returns (stream SPFResponse);
}
```

### 4.4 Policy Simulator

**Priority:** P3 - Low
**Timeline:** 1 week

**Web-based tool to:**
- Test SPF records before deployment
- Simulate various scenarios
- Visualize SPF evaluation flow
- Identify potential issues

---

## Phase 5: Advanced Features

### 5.1 SPF Record Database

**Priority:** P3 - Low
**Timeline:** 3 weeks

**Features:**
- Pre-fetch and cache SPF records
- Periodic updates (hourly/daily)
- Reduce DNS load
- Fast lookups

```go
type SPFDatabase struct {
    db    *sql.DB
    cache *bigcache.BigCache
}

func (d *SPFDatabase) GetRecord(domain string) (*SPF, error)
func (d *SPFDatabase) UpdateRecords(domains []string) error
```

### 5.2 Machine Learning Integration

**Priority:** P4 - Future
**Timeline:** 4-6 weeks

**Features:**
- Anomaly detection
- Spam sender pattern recognition
- Risk scoring
- Adaptive thresholds

```go
type MLScorer struct {
    model *tensorflow.Model
}

func (s *MLScorer) ScoreMessage(features MessageFeatures) float64
```

**Features to analyze:**
- SPF result
- DKIM signatures
- DMARC policy
- Sender reputation
- Historical patterns
- Message content

---

## Implementation Priority

### Q1 2025
- ✅ SPF Library Modernization (COMPLETED)
- 🚧 DMARC Integration (6 weeks)
- 🚧 DKIM Support (6 weeks)

### Q2 2025
- DNS-over-HTTPS (2 weeks)
- Advanced Caching (Redis/LRU) (2 weeks)
- Prometheus Metrics (2 weeks)
- SPF Validation CLI (1 week)

### Q3 2025
- REST API Service (2 weeks)
- Rate Limiting (2 weeks)
- OpenTelemetry Tracing (1 week)
- Policy Simulator (1 week)

### Q4 2025
- gRPC Service (2 weeks)
- SPF Record Database (3 weeks)
- Machine Learning POC (4 weeks)

---

## Dependencies

### Required Libraries (DMARC/DKIM)
```go
// Cryptography
"crypto/rsa"
"crypto/sha256"
"crypto/ed25519" // Optional for ED25519

// Email parsing
"net/mail"
"mime"
"mime/multipart"

// Existing
"context"
"net"
"time"
```

### Optional Libraries (Future)
```go
// Caching
"github.com/go-redis/redis/v8"
"github.com/bradfitz/gomemcache"
"github.com/allegro/bigcache/v3"
"github.com/hashicorp/golang-lru"

// Metrics
"github.com/prometheus/client_golang/prometheus"
"go.opentelemetry.io/otel"

// Logging
"go.uber.org/zap"
"github.com/sirupsen/logrus"

// Web/API
"github.com/gin-gonic/gin"
"google.golang.org/grpc"
```

---

## Success Metrics

### Code Quality
- Test coverage >80% for all new features
- Zero linting issues
- Comprehensive documentation

### Performance
- DMARC evaluation <5ms
- DKIM verification <20ms (RSA-2048)
- Combined auth <50ms

### Adoption
- 100+ stars on GitHub
- 10+ production deployments
- Active community contributions

---

## Contributing

We welcome contributions! Priority areas:
1. DMARC implementation
2. DKIM verification
3. Test coverage improvements
4. Documentation enhancements

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## Resources

### RFCs
- [RFC 7208](https://tools.ietf.org/html/rfc7208) - SPF
- [RFC 7489](https://tools.ietf.org/html/rfc7489) - DMARC
- [RFC 6376](https://tools.ietf.org/html/rfc6376) - DKIM
- [RFC 8484](https://tools.ietf.org/html/rfc8484) - DNS over HTTPS

### Testing Resources
- [DMARC.org Test Suite](https://dmarc.org/resources/tools/)
- [DKIMValidator.com](https://dkimvalidator.com/)
- [MXToolbox](https://mxtoolbox.com/)

---

**Last Updated:** 2025-01-10
**Version:** 1.0
**Status:** Active Development
