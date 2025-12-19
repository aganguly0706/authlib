# Security Practices Implementation Guide

This document outlines the comprehensive security practices implemented in AuthLib RBAC Authorization Library, ensuring enterprise-grade security and compliance.

## 1. Least Privilege & Default Deny

### Implementation
- **Default Deny**: All authorization decisions start with `false` and require explicit grants
- **Per-Function Policies**: Each function can have specific policy requirements
- **Minimal Permissions**: Users receive only the minimum permissions needed for their role

### Code Examples
```php
// Default deny in PolicyEnforcer
public function enforce(string $userId, string $permission, array $context = []): bool
{
    // Default deny - no policies means no access
    if (empty($this->policies) && !isset($this->functionPolicies[$permission])) {
        return false;
    }
    // ... policy evaluation
}

// Per-function policy enforcement
$enforcer->addFunctionPolicy('Users.Delete', PolicyEnforcer::leastPrivilegePolicy(
    requiredRoles: ['admin'],
    allowedIps: ['192.168.1.0/24'],
    requireMfa: true
));
```

### Best Practices
- Start with no permissions and add only what's necessary
- Regular access reviews to remove unused permissions
- Use granular permissions rather than broad roles
- Implement approval workflows for sensitive permissions

## 2. JWT Validation Security

### Implementation
- **Comprehensive Validation**: Signature, issuer, audience, exp/nbf claims
- **Clock Skew Handling**: ±60 seconds tolerance (configurable, max 5 minutes)
- **Algorithm Security**: Only secure algorithms allowed (RS256, PS256, ES256, etc.)
- **Token Age Limits**: Maximum token age enforcement

### Security Measures
```php
// Clock skew tolerance in OidcTokenValidator
private int $clockSkewTolerance = 60; // ±60 seconds for clock skew
private int $maxTokenAge = 3600; // Maximum token age in seconds

// Algorithm validation
private function validateAlgorithm(stdClass $header): void
{
    $allowedAlgorithms = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512'];
    
    if (!in_array($header->alg, $allowedAlgorithms, true)) {
        throw new InvalidArgumentException('Unsupported or insecure algorithm: ' . $header->alg);
    }
    
    // Explicitly deny 'none' algorithm
    if ($header->alg === 'none') {
        throw new InvalidArgumentException('Algorithm "none" is not allowed');
    }
}

// Claims validation with clock skew
if ($payload->exp < ($now - $this->clockSkewTolerance)) {
    throw new ExpiredException('Token has expired');
}
```

### Configuration
```env
# Token security settings
TOKEN_MAX_AGE=3600          # 1 hour maximum
CLOCK_SKEW_TOLERANCE=60     # ±60 seconds
OIDC_ISSUER=https://auth.company.com
OIDC_AUDIENCE=my-application
```

## 3. Short Token TTL & Cache Alignment

### Implementation
- **TTL Enforcement**: Cache never exceeds token TTL
- **Dynamic TTL**: Cache TTL adjusts based on token expiration
- **Cache Invalidation**: Immediate invalidation on permission changes

### Code Implementation
```php
// Cache TTL enforcement in PermissionCache
public function set(string $key, mixed $value, ?int $ttl = null): void
{
    $ttl = $ttl ?? $this->defaultTtl;
    
    // Enforce maximum TTL - never cache longer than token TTL
    $ttl = min($ttl, $this->maxTtl);
    
    $this->cache[$key] = [
        'value' => $value,
        'expires' => time() + $ttl,
        'created' => time()
    ];
}
```

### Best Practices
- Keep token TTL short (15-60 minutes)
- Use refresh tokens for longer sessions
- Cache permissions for no longer than token validity
- Clear cache on permission changes

## 4. Key Rotation & JWKS Strategy

### Implementation
- **JWKS URI Support**: Automatic key fetching with caching
- **Cache Management**: TTL-based JWKS cache with manual refresh capability
- **Multiple Key Support**: Handles key rotation gracefully
- **Fallback Strategy**: X.509 certificate chain support

### Configuration Options
```php
// Option 1: JWKS URI (Recommended)
$validator = new OidcTokenValidator(
    issuer: $_ENV['OIDC_ISSUER'],
    audience: $_ENV['OIDC_AUDIENCE'],
    jwksUri: $_ENV['OIDC_JWKS_URI'],
    cacheTtl: 3600 // 1 hour cache
);

// Option 2: Static key for testing
$validator = new OidcTokenValidator(
    issuer: $_ENV['OIDC_ISSUER'],
    audience: $_ENV['OIDC_AUDIENCE'],
    staticJwks: ['kid1' => $publicKey]
);
```

### Key Rotation Process
1. New key added to JWKS endpoint
2. AuthLib automatically fetches updated JWKS
3. Tokens signed with old keys continue to work during transition
4. Old keys removed from JWKS after all tokens expire
5. Cache automatically updates on next validation

## 5. Comprehensive Audit Logging

### Implementation
- **All Decisions**: Every grant and denial logged with full context
- **Policy Versioning**: Bindings hash tracks policy changes
- **Security Events**: Suspicious activity and security violations
- **Structured Logging**: PSR-3 compatible with rich metadata

### Audit Data Structure
```php
// Authorization decision audit
$auditData = [
    'event_type' => 'authorization_decision',
    'timestamp' => gmdate('c'),
    'user_id' => $this->sanitizeUserId($userId),
    'permission' => $this->sanitizePermission($permission),
    'result' => $granted ? 'granted' : 'denied',
    'policy_version' => $this->bindingsHash,  // Policy versioning
    'context' => $this->sanitizeContext($context),
    'request_id' => $context['request_id'] ?? $this->generateRequestId(),
    'ip_address' => $context['ip_address'] ?? null,
    'cache_used' => $context['cache_used'] ?? false,
    'denial_reason' => $granted ? null : ($context['reason'] ?? 'Insufficient permissions')
];
```

### Policy Version Tracking
```php
// Generate policy version hash
public function generateBindingsHash(): string
{
    $stmt = $this->pdo->prepare('
        SELECT MAX(GREATEST(
            COALESCE(MAX(ur.created_at), "1970-01-01"),
            COALESCE(MAX(up.created_at), "1970-01-01"),
            COALESCE(MAX(rp.created_at), "1970-01-01"),
            COALESCE(MAX(gr.created_at), "1970-01-01")
        )) as last_change
        FROM user_roles ur, user_permissions up, role_permissions rp, group_roles gr
    ');
    // ... hash generation based on change timestamps
}
```

## 6. Config as Code

### Migration Management
- **Versioned Migrations**: Database schema changes tracked in version control
- **Rollback Support**: Each migration includes rollback procedures
- **Environment Separation**: Dev seeds vs production migrations

### Directory Structure
```
database/
├── migrations/
│   ├── 0001_init.sql
│   ├── 0002_add_audit_tables.sql
│   └── 0003_add_indexes.sql
└── seeds/
    ├── dev_sample_data.sql      # Development only
    └── production_roles.sql     # Production-safe base roles
```

### Migration Example
```sql
-- 0002_add_audit_tables.sql
-- Migration: Add audit logging tables
-- Version: 0002
-- Date: 2025-12-18

CREATE TABLE audit_logs (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    event_type VARCHAR(100) NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    permission VARCHAR(100),
    result ENUM('granted', 'denied') NOT NULL,
    policy_version VARCHAR(64) NOT NULL,
    context JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_id (user_id),
    INDEX idx_event_type (event_type),
    INDEX idx_created_at (created_at)
);

-- Rollback:
-- DROP TABLE audit_logs;
```

## 7. Prepared Statements & Input Sanitization

### SQL Security
- **100% Prepared Statements**: No string concatenation in SQL
- **Input Sanitization**: All user inputs sanitized before processing
- **Type Validation**: Strict type checking on all parameters

### Implementation Examples
```php
// Always use prepared statements
$stmt = $this->pdo->prepare('
    SELECT permission FROM user_permissions 
    WHERE user_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL 1 YEAR)
');
$stmt->execute([$userId]);

// Input sanitization
private function sanitizeUserId(string $userId): string
{
    // Remove control characters and limit length
    $sanitized = preg_replace('/[\x00-\x1F\x7F]/', '', trim($userId));
    
    // Only allow alphanumeric, email characters, and common separators
    $sanitized = preg_replace('/[^A-Za-z0-9@._-]/', '', $sanitized);
    
    // Limit length to prevent buffer overflows
    return substr($sanitized, 0, 255);
}

// Group ID sanitization (handles AD DNs)
private function sanitizeGroupId(string $groupId): string
{
    $sanitized = preg_replace('/[\x00-\x1F\x7F]/', '', trim($groupId));
    $sanitized = preg_replace('/[^\x20-\x7E]/', '', $sanitized); // Printable ASCII only
    $sanitized = str_replace(['--', '/*', '*/', ';', '\x00'], '', $sanitized);
    return substr($sanitized, 0, 500);
}
```

### Validation Rules
- **User IDs**: Alphanumeric + email chars, max 255 characters
- **Permissions**: Alphanumeric + dots/underscores/hyphens, max 100 characters
- **Roles**: Alphanumeric + underscores/hyphens, max 50 characters
- **Group IDs**: Printable ASCII (for AD DNs), max 500 characters, no SQL injection chars

## 8. Observability & Metrics

### Metrics Collection
- **Cache Performance**: Hit rates, miss rates, memory usage
- **Authorization Patterns**: Denial rates, permission usage
- **Security Events**: Failed attempts, policy violations

### Metrics Implementation
```php
// Cache metrics in PermissionCache
public function getMetrics(): array
{
    $totalRequests = $this->metrics['hits'] + $this->metrics['misses'];
    $hitRate = $totalRequests > 0 ? $this->metrics['hits'] / $totalRequests : 0;
    $denialRate = $this->metrics['sets'] > 0 ? $this->metrics['denials'] / $this->metrics['sets'] : 0;
    
    return [
        'hits' => $this->metrics['hits'],
        'misses' => $this->metrics['misses'],
        'hit_rate' => round($hitRate * 100, 2),
        'denial_rate' => round($denialRate * 100, 2),
        'total_entries' => count($this->cache),
        'memory_usage' => $this->estimateMemoryUsage()
    ];
}
```

### Monitoring Endpoints
```php
// Example monitoring endpoint
Route::get('/metrics/auth', function() {
    return response()->json([
        'cache' => $cache->getMetrics(),
        'repository' => $repository->getCacheStats(),
        'policy_version' => $audit->getPolicyVersion(),
        'uptime' => time() - $startTime
    ]);
});
```

### Key Metrics to Monitor
- **Cache Hit Rate**: Should be >80% for good performance
- **Denial Rate**: Monitor for unusual patterns or attacks
- **Policy Version Changes**: Track when permissions are modified
- **Response Times**: Authorization decision latency
- **Error Rates**: Failed token validations, database errors

## Security Configuration Checklist

### Environment Variables
```env
# Required Security Settings
OIDC_ISSUER=https://your-auth-server.com
OIDC_AUDIENCE=your-app-id
OIDC_JWKS_URI=https://your-auth-server.com/.well-known/jwks
TOKEN_MAX_AGE=3600
AUTH_CACHE_TTL=600
CLOCK_SKEW_TOLERANCE=60

# Audit Configuration
AUDIT_ENABLED=true
LOG_LEVEL=info

# Database Security
DB_SSL_MODE=required
DB_SSL_VERIFY_CERT=true
```

### Production Deployment
1. **Enable HTTPS**: All communication must be encrypted
2. **Database SSL**: Encrypt database connections
3. **Log Rotation**: Configure log rotation for audit files
4. **Monitoring**: Set up alerts for high denial rates
5. **Backup Strategy**: Regular backups of authorization data
6. **Access Controls**: Restrict database access to authorized systems

### Security Headers
```php
// Add security headers in middleware
$response->headers->set('X-Content-Type-Options', 'nosniff');
$response->headers->set('X-Frame-Options', 'DENY');
$response->headers->set('X-XSS-Protection', '1; mode=block');
$response->headers->set('Strict-Transport-Security', 'max-age=31536000');
```

## Compliance & Standards

### Supported Standards
- **SOX Compliance**: Comprehensive audit trails with policy versioning
- **HIPAA**: Detailed access logging and user activity tracking
- **GDPR**: User permission tracking and audit capabilities
- **PCI DSS**: Strong authentication and access controls

### Audit Requirements Met
- ✅ All authorization decisions logged
- ✅ Policy changes tracked with versioning
- ✅ User activity correlation via request IDs
- ✅ Tamper-evident logs with structured data
- ✅ Retention policies configurable
- ✅ Export capabilities for compliance reporting