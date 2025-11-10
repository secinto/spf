# email-validator

A comprehensive command-line tool for validating email messages using SPF, DKIM, and DMARC authentication.

## Features

- **Complete Email Authentication**: Validates SPF, DKIM, and DMARC in one command
- **Multiple Output Formats**: Human-readable output with Unicode symbols or JSON for automation
- **Detailed Results**: Shows alignment status, policy recommendations, and Authentication-Results header
- **File Support**: Can parse and validate EML format email files
- **Fast & Efficient**: Uses DNS caching for improved performance
- **Production Ready**: Proper timeout handling and error reporting

## Installation

```bash
# From source
cd cmd/email-validator
go build

# Or install to $GOPATH/bin
go install github.com/asggo/spf/cmd/email-validator@latest
```

## Usage

### Basic SPF Check

The simplest use case - validate the envelope sender against SPF record:

```bash
email-validator -ip 192.0.2.1 -from sender@example.com
```

### Full Email Validation

Validate a complete email message with DKIM and DMARC:

```bash
email-validator -ip 192.0.2.1 -from sender@example.com -file message.eml
```

### Verbose Output

Get detailed information including errors and Authentication-Results header:

```bash
email-validator -ip 192.0.2.1 -from sender@example.com -file message.eml -verbose
```

### JSON Output

Perfect for automation and integration with other tools:

```bash
email-validator -ip 192.0.2.1 -from sender@example.com -file message.eml -json
```

## Command-Line Flags

| Flag | Type | Required | Description |
|------|------|----------|-------------|
| `-ip` | string | Yes | IP address of the sending mail server |
| `-from` | string | Yes | Envelope sender address (MAIL FROM) |
| `-header-from` | string | No | Header From address (extracted from file if not provided) |
| `-file` | string | No | Path to email file in EML format |
| `-verbose` | bool | No | Show detailed authentication results |
| `-json` | bool | No | Output results in JSON format |
| `-timeout` | duration | No | DNS lookup timeout (default: 10s) |

## Output Format

### Human-Readable Output

The default output provides a clear, visual representation of authentication results:

```
╔════════════════════════════════════════════════════════════════╗
║           EMAIL AUTHENTICATION VALIDATION RESULTS              ║
╚════════════════════════════════════════════════════════════════╝

✅ AUTHENTICATION: PASS
   Reason: DMARC pass

┌─ SPF (Sender Policy Framework)
│  Result: ✅ Pass
│  Domain: example.com
└─

┌─ DKIM (DomainKeys Identified Mail)
│  Signature #1: ✅ VALID
│    Domain:   example.com
│    Selector: default
└─

┌─ DMARC (Domain-based Message Authentication)
│  Result:     ✅ PASS
│  Policy:     REJECT
│  Action:     REJECT
│  Domain:     example.com
│  Alignment:
│    SPF:  ✅
│    DKIM: ✅
└─

┌─ RECOMMENDED ACTION
│  ✅ DELIVER - Email passed authentication
└─

═══════════════════════════════════════════════════════════════
✅ EMAIL PASSED AUTHENTICATION - SAFE TO DELIVER
═══════════════════════════════════════════════════════════════
```

### JSON Output

```json
{
  "authenticated": true,
  "reason": "DMARC pass",
  "spf": {
    "result": "Pass",
    "domain": "example.com"
  },
  "dkim": [
    {
      "valid": true,
      "domain": "example.com",
      "selector": "default"
    }
  ],
  "dmarc": {
    "policy": "reject",
    "disposition": "reject",
    "spf_aligned": true,
    "dkim_aligned": true,
    "domain": "example.com"
  },
  "authentication_header": "Authentication-Results: localhost; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com header.s=default; dmarc=pass header.from=example.com",
  "recommended_action": "DELIVER"
}
```

## Exit Codes

- `0`: Email passed authentication
- `1`: Email failed authentication or error occurred

This allows easy integration in shell scripts:

```bash
if email-validator -ip "$IP" -from "$FROM" -file "$FILE" -json > result.json; then
    echo "Authentication passed"
    # Deliver email
else
    echo "Authentication failed"
    # Handle rejection/quarantine
fi
```

## Examples

### Example 1: Quick SPF Check

```bash
$ email-validator -ip 192.0.2.1 -from admin@company.com

╔════════════════════════════════════════════════════════════════╗
║           EMAIL AUTHENTICATION VALIDATION RESULTS              ║
╚════════════════════════════════════════════════════════════════╝

✅ AUTHENTICATION: PASS
   Reason: SPF pass (no DMARC)

┌─ SPF (Sender Policy Framework)
│  Result: ✅ Pass
│  Domain: company.com
└─

┌─ DKIM (DomainKeys Identified Mail)
│  Result: ⚠️  No DKIM signatures found
└─

┌─ DMARC (Domain-based Message Authentication)
│  Result: ⚠️  No DMARC policy found
└─

┌─ RECOMMENDED ACTION
│  ✅ DELIVER - Email passed authentication
└─

═══════════════════════════════════════════════════════════════
✅ EMAIL PASSED AUTHENTICATION - SAFE TO DELIVER
═══════════════════════════════════════════════════════════════
```

### Example 2: Validate Email File

```bash
$ email-validator -ip 198.51.100.1 -from phishing@evil.com -file suspicious.eml -verbose

╔════════════════════════════════════════════════════════════════╗
║           EMAIL AUTHENTICATION VALIDATION RESULTS              ║
╚════════════════════════════════════════════════════════════════╝

❌ AUTHENTICATION: FAIL
   Reason: DMARC policy=reject

┌─ SPF (Sender Policy Framework)
│  Result: ❌ Fail
│  Domain: evil.com
│  Error:  No authorized IPs for domain
└─

┌─ DKIM (DomainKeys Identified Mail)
│  Signature #1: ❌ INVALID
│    Domain:   evil.com
│    Selector: default
│    Error:    DKIM key not found in DNS
└─

┌─ DMARC (Domain-based Message Authentication)
│  Result:     ❌ FAIL
│  Policy:     REJECT
│  Action:     REJECT
│  Domain:     evil.com
│  Alignment:
│    SPF:  ❌
│    DKIM: ❌
└─

┌─ RECOMMENDED ACTION
│  🚫 REJECT - Email should be rejected
└─

═══════════════════════════════════════════════════════════════
⚠️  EMAIL FAILED AUTHENTICATION - HANDLE WITH CAUTION
═══════════════════════════════════════════════════════════════
```

### Example 3: JSON for Automation

```bash
$ email-validator -ip 192.0.2.1 -from sender@example.com -file email.eml -json | jq .

{
  "authenticated": false,
  "reason": "DMARC policy=quarantine",
  "spf": {
    "result": "Pass",
    "domain": "example.com"
  },
  "dkim": [
    {
      "valid": false,
      "domain": "example.com",
      "selector": "default",
      "error": "body hash does not match"
    }
  ],
  "dmarc": {
    "policy": "quarantine",
    "disposition": "quarantine",
    "spf_aligned": true,
    "dkim_aligned": false,
    "domain": "example.com"
  },
  "recommended_action": "QUARANTINE"
}
```

## Integration Examples

### Mail Server Integration

```bash
#!/bin/bash
# Postfix content filter integration

# Read email from stdin
EMAIL_FILE=$(mktemp)
cat > "$EMAIL_FILE"

# Extract envelope sender and IP from Postfix
SENDER="$1"
IP="$2"

# Validate
if email-validator -ip "$IP" -from "$SENDER" -file "$EMAIL_FILE" -json > /tmp/auth-result.json; then
    # Authentication passed
    /usr/sbin/sendmail -G -i "$@" < "$EMAIL_FILE"
    EXIT_CODE=$?
else
    # Authentication failed - check recommendation
    ACTION=$(jq -r .recommended_action /tmp/auth-result.json)

    case "$ACTION" in
        REJECT)
            # Return permanent failure
            exit 67  # EX_NOUSER
            ;;
        QUARANTINE)
            # Add X-Spam header and deliver to spam folder
            sed -i '1i X-Spam-Status: Yes (Failed DMARC)' "$EMAIL_FILE"
            /usr/sbin/sendmail -G -i "$@" < "$EMAIL_FILE"
            EXIT_CODE=$?
            ;;
        *)
            # Deliver with warning header
            sed -i '1i X-Authentication-Warning: SPF/DKIM/DMARC checks failed' "$EMAIL_FILE"
            /usr/sbin/sendmail -G -i "$@" < "$EMAIL_FILE"
            EXIT_CODE=$?
            ;;
    esac
fi

rm -f "$EMAIL_FILE" /tmp/auth-result.json
exit $EXIT_CODE
```

### Monitoring Script

```bash
#!/bin/bash
# Monitor email authentication over time

LOGFILE="/var/log/email-auth.log"

while read -r IP FROM FILE; do
    RESULT=$(email-validator -ip "$IP" -from "$FROM" -file "$FILE" -json 2>/dev/null)

    AUTHENTICATED=$(echo "$RESULT" | jq -r .authenticated)
    SPF=$(echo "$RESULT" | jq -r .spf.result)
    DKIM=$(echo "$RESULT" | jq -r '.dkim[0].valid // false')
    DMARC=$(echo "$RESULT" | jq -r .dmarc.policy)

    echo "$(date -Iseconds) | FROM=$FROM | IP=$IP | AUTH=$AUTHENTICATED | SPF=$SPF | DKIM=$DKIM | DMARC=$DMARC" >> "$LOGFILE"
done
```

## Understanding Results

### SPF Results

- **Pass** ✅: IP is authorized to send for this domain
- **Fail** ❌: IP is explicitly not authorized
- **SoftFail** ⚠️: IP is probably not authorized (treat as suspicious)
- **Neutral** ⚪: No statement about authorization
- **None** ⚫: No SPF record found
- **TempError/PermError** 🔴: DNS lookup or parsing error

### DKIM Results

- **Valid** ✅: Signature verifies correctly
- **Invalid** ❌: Signature does not verify (tampering or configuration issue)
- **No signatures found** ⚠️: Email not signed with DKIM

### DMARC Results

- **Pass** ✅: At least SPF or DKIM aligned with policy
- **Fail** ❌: Neither SPF nor DKIM aligned
- **No policy** ⚠️: Domain has no DMARC record

### Recommended Actions

- **DELIVER**: Email passed authentication, safe to deliver normally
- **REJECT**: Email should be rejected (hard bounce)
- **QUARANTINE**: Move to spam/junk folder
- **DELIVER_WITH_WARNING**: Deliver but flag as suspicious

## Performance

- Uses DNS caching to minimize lookups
- Typical validation time: 50-200ms (with warm cache)
- Can process 100+ emails/second with proper caching
- Configurable timeout for slow DNS servers

## Limitations

- Requires network access for DNS lookups
- Cannot validate emails after they've been forwarded (SPF breaks)
- DKIM validation requires the complete, unmodified email
- DNS cache is not persistent between invocations

## See Also

- [SPF Package Documentation](../../spf/)
- [DKIM Package Documentation](../../dkim/)
- [DMARC Package Documentation](../../dmarc/)
- [Auth Package Documentation](../../auth/)

## License

See the main project [LICENSE](../../LICENSE) file.
