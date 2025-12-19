# AuthLib - Role-Based Access Control (RBAC) Authorization Library

[![PHP Version](https://img.shields.io/badge/php-%5E8.2-blue)](https://www.php.net/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/authlib/rbac-authorization)

A comprehensive PHP authorization library implementing Role-Based Access Control (RBAC) with Active Directory group integration, JWT token validation, and fine-grained permission management.

## What This Library Does

AuthLib provides a complete RBAC solution that follows this authorization flow:

```
Active Directory Groups → Roles → Permissions → Function-Level Access
```

### Core Features

- **RBAC Implementation**: Complete role-based access control with hierarchical permissions
- **AD Group Integration**: Maps Active Directory groups to application roles automatically
- **JWT/OIDC Support**: Full OpenID Connect integration with PingFederate and other providers
- **SAML 2.0 Support**: Complete SAML assertion validation with signature verification and claims extraction
- **Permission Caching**: High-performance PSR-6 compliant caching for authorization decisions
- **Audit Logging**: Comprehensive audit trails using PSR-3 compatible loggers (Monolog)
- **Policy Enforcement**: Fine-grained policy engines (time-based, IP-based, resource ownership)
- **Database Agnostic**: PDO-based repository with MySQL optimization
- **Framework Integration**: Ready-to-use middleware for Laravel, Slim, and plain PHP

### Authorization Flow

1. **Authentication**: User authenticates via OIDC/JWT with PingFederate
2. **Group Extraction**: JWT claims contain AD group memberships
3. **Role Mapping**: Groups are mapped to application roles in the database
4. **Permission Resolution**: Roles grant specific permissions to users
5. **Function-Level Control**: Permissions control access to specific application functions
6. **Policy Enforcement**: Additional policies (time, IP, ownership) can further restrict access
7. **Audit Logging**: All authorization decisions are logged for compliance

## Installation

Install via Composer:

```bash
composer require authlib/rbac-authorization
```

### Requirements

- PHP 8.2 or higher
- PDO extension with MySQL/PostgreSQL driver
- OpenSSL extension (for JWT validation)

## Quick Start

### 1. Database Setup

Run the included migrations to set up the RBAC tables:

```bash
# Create database tables
php vendor/bin/authlib migrate

# Seed with sample data (optional)
php vendor/bin/authlib seed
```

Or run the SQL manually:

```sql
-- Run the migration file
mysql -u your_user -p your_database < vendor/authlib/rbac-authorization/database/migrations/0001_init.sql

-- Optional: Load sample data
mysql -u your_user -p your_database < vendor/authlib/rbac-authorization/database/seeds/sample_seed.sql
```

### 2. Environment Configuration

Create a `.env` file with your configuration:

```env
# Database Configuration
DB_HOST=localhost
DB_PORT=3306
DB_DATABASE=your_app
DB_USERNAME=your_user
DB_PASSWORD=your_password

# OIDC Configuration (PingFederate)
OIDC_ISSUER=https://your-pingfederate.example.com
OIDC_AUDIENCE=your-application-id
OIDC_JWKS_URI=https://your-pingfederate.example.com/.well-known/jwks

# Security Settings
AUTH_CACHE_TTL=600
TOKEN_MAX_AGE=3600

# Audit Settings
LOG_LEVEL=info
AUDIT_ENABLED=true
```

### 3. Basic Usage

```php
<?php
require 'vendor/autoload.php';

use authlib\Auth\Core\AuthorizationService;
use authlib\Auth\Data\PdoBindingsRepository;
use authlib\Auth\Config\DbConfig;
use authlib\Auth\Audit\LoggerAuditSink;
use authlib\Auth\Core\PermissionCache;

// Load environment
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

// Setup components
$pdo = DbConfig::pdoFromEnv();
$repository = new PdoBindingsRepository($pdo);
$audit = new LoggerAuditSink(new Monolog\Logger('authz'));
$cache = new PermissionCache();

// Create authorization service
$auth = new AuthorizationService($repository, $audit, $cache);

// Check permissions
$hasPermission = $auth->hasPermission('user@example.com', 'Orders.Edit', [
    'roles' => ['manager'],
    'groups' => ['sales_team'],
    'ip_address' => $_SERVER['REMOTE_ADDR']
]);

if ($hasPermission) {
    echo "Access granted to edit orders";
} else {
    echo "Access denied";
}
```

## PingFederate OIDC Integration

### JWT Claims Structure

AuthLib expects JWT tokens from PingFederate to contain the following claims:

```json
{
  "iss": "https://your-pingfederate.example.com",
  "aud": "your-application-id", 
  "sub": "user@domain.com",
  "exp": 1640995200,
  "iat": 1640991600,
  "groups": [
    "CN=Sales_Team,OU=Groups,DC=company,DC=com",
    "CN=Managers,OU=Groups,DC=company,DC=com"
  ],
  "roles": ["manager", "sales_user"],
  "email": "user@domain.com",
  "name": "John Doe"
}
```

### OIDC Validator Setup

```php
use authlib\Auth\Auth\OidcTokenValidator;
use authlib\Auth\Auth\DefaultClaimsExtractor;

// Initialize OIDC validator
$validator = new OidcTokenValidator(
    issuer: $_ENV['OIDC_ISSUER'],
    audience: $_ENV['OIDC_AUDIENCE'],
    jwksUri: $_ENV['OIDC_JWKS_URI']
);

// Setup claims extractor
$claimsExtractor = new DefaultClaimsExtractor();

// Validate and extract claims
try {
    $payload = $validator->validate($jwtToken);
    $claims = $claimsExtractor->extractClaims($payload);
    
    $userId = $claims['user_id'];
    $groups = $claims['groups'];
    $roles = $claims['roles'];
} catch (Exception $e) {
    // Handle invalid token
    throw new AuthenticationException('Invalid token: ' . $e->getMessage());
}
```

### Group Mapping Configuration

Map Active Directory groups to application roles:

```php
// Map AD groups to roles in database
$repository->bindRoleToGroup('CN=Sales_Team,OU=Groups,DC=company,DC=com', 'sales_user');
$repository->bindRoleToGroup('CN=Managers,OU=Groups,DC=company,DC=com', 'manager');
$repository->bindRoleToGroup('CN=Administrators,OU=Groups,DC=company,DC=com', 'admin');

// Define role permissions
$repository->bindPermissionToRole('admin', 'Users.Create');
$repository->bindPermissionToRole('admin', 'Users.Delete');
$repository->bindPermissionToRole('manager', 'Orders.Edit');
$repository->bindPermissionToRole('manager', 'Reports.View');
$repository->bindPermissionToRole('sales_user', 'Orders.View');
```

## SAML 2.0 Integration

### SAML Assertion Structure

AuthLib supports SAML 2.0 assertion validation with the following expected assertion format:

```xml
<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml2:Issuer>https://your-idp.example.com</saml2:Issuer>
  <saml2:Subject>
    <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@domain.com</saml2:NameID>
  </saml2:Subject>
  <saml2:Conditions>
    <saml2:AudienceRestriction>
      <saml2:Audience>your-sp-entity-id</saml2:Audience>
    </saml2:AudienceRestriction>
  </saml2:Conditions>
  <saml2:AttributeStatement>
    <saml2:Attribute Name="groups">
      <saml2:AttributeValue>CN=Sales_Team,OU=Groups,DC=company,DC=com</saml2:AttributeValue>
      <saml2:AttributeValue>CN=Managers,OU=Groups,DC=company,DC=com</saml2:AttributeValue>
    </saml2:Attribute>
    <saml2:Attribute Name="roles">
      <saml2:AttributeValue>manager</saml2:AttributeValue>
      <saml2:AttributeValue>sales_user</saml2:AttributeValue>
    </saml2:Attribute>
    <saml2:Attribute Name="email">
      <saml2:AttributeValue>user@domain.com</saml2:AttributeValue>
    </saml2:Attribute>
    <saml2:Attribute Name="name">
      <saml2:AttributeValue>John Doe</saml2:AttributeValue>
    </saml2:Attribute>
  </saml2:AttributeStatement>
</saml2:Assertion>
```

### SAML Configuration

Configure SAML assertion validation in your environment:

```env
# SAML Identity Provider Configuration
SAML_IDP_ISSUER=https://your-idp.example.com
SAML_SP_ENTITY_ID=your-application-sp-id
SAML_IDP_CERTIFICATE_FINGERPRINTS=ABC123DEF456,789GHI012JKL
SAML_MAX_ASSERTION_AGE=3600
SAML_CLOCK_SKEW=300
```

### SAML Validator Setup

```php
use authlib\Auth\Auth\SamlAssertionValidator;
use authlib\Auth\Auth\DefaultClaimsExtractor;

// Initialize SAML validator
$samlConfig = [
    'entity_id' => $_ENV['SAML_SP_ENTITY_ID'],
    'certificate_fingerprints' => explode(',', $_ENV['SAML_IDP_CERTIFICATE_FINGERPRINTS']),
    'issuer' => $_ENV['SAML_IDP_ISSUER'],
    'max_assertion_age' => (int)$_ENV['SAML_MAX_ASSERTION_AGE'],
    'clock_skew' => (int)$_ENV['SAML_CLOCK_SKEW']
];

$validator = new SamlAssertionValidator($samlConfig);

// Validate and extract claims from SAML assertion
try {
    $samlAssertion = $_POST['SAMLResponse']; // Base64 encoded SAML assertion
    $claims = $validator->validate($samlAssertion);
    
    $userId = $claims->sub;
    $groups = $claims->groups ?? [];
    $roles = $claims->roles ?? [];
    $email = $claims->email;
    $name = $claims->name;
    
    // Use claims for authorization
    $hasPermission = $auth->hasPermission($userId, 'Orders.Edit', [
        'groups' => $groups,
        'roles' => $roles
    ]);
    
} catch (Exception $e) {
    // Handle invalid SAML assertion
    throw new AuthenticationException('Invalid SAML assertion: ' . $e->getMessage());
}
```

### SAML Claims Processing

The SAML validator extracts and processes the following claims:

```php
// Expected SAML claims structure after validation
$claims = (object) [
    'iss' => 'https://your-idp.example.com',
    'aud' => 'your-sp-entity-id',
    'sub' => 'user@domain.com',
    'iat' => 1703851200,
    'exp' => 1703854800,
    'name_id_format' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    'session_index' => 'session_abc123',
    'auth_time' => 1703851200,
    'acr' => 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
    'groups' => [
        'CN=Sales_Team,OU=Groups,DC=company,DC=com',
        'CN=Managers,OU=Groups,DC=company,DC=com'
    ],
    'roles' => ['manager', 'sales_user'],
    'email' => 'user@domain.com',
    'name' => 'John Doe'
];
```

### SAML Security Features

AuthLib's SAML validator includes comprehensive security validations:

#### 1. Signature Verification
```php
// Validates XML signature using IdP certificates
$validator->validateSignature($assertion, $certificateFingerprints);
```

#### 2. Assertion Validation
```php
// Validates all required SAML assertion elements:
// - Issuer matches expected IdP
// - Audience matches SP entity ID
// - Assertion is not expired
// - Time constraints are respected (NotBefore, NotOnOrAfter)
// - Subject confirmation is valid
```

#### 3. Anti-Replay Protection
```php
// Prevents assertion replay attacks
$assertionId = $claims->assertion_id;
if ($this->isAssertionUsed($assertionId)) {
    throw new SecurityException('Assertion replay detected');
}
$this->markAssertionUsed($assertionId, $claims->exp);
```

### SAML Integration Examples

#### Laravel SAML Middleware

```php
<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use authlib\Auth\Auth\SamlAssertionValidator;
use authlib\Auth\Contracts\AuthorizationServiceInterface;

class SamlAuthMiddleware
{
    public function __construct(
        private SamlAssertionValidator $samlValidator,
        private AuthorizationServiceInterface $auth
    ) {}

    public function handle(Request $request, Closure $next, string $permission)
    {
        $samlResponse = $request->input('SAMLResponse');
        
        if (!$samlResponse) {
            return redirect()->route('saml.login');
        }
        
        try {
            $claims = $this->samlValidator->validate($samlResponse);
            
            $hasPermission = $this->auth->hasPermission(
                $claims->sub,
                $permission,
                [
                    'groups' => $claims->groups,
                    'roles' => $claims->roles,
                    'ip_address' => $request->ip()
                ]
            );
            
            if (!$hasPermission) {
                abort(403, 'Insufficient permissions');
            }
            
            // Store claims in request for downstream use
            $request->merge([
                'auth_user_id' => $claims->sub,
                'auth_claims' => $claims,
                'auth_groups' => $claims->groups,
                'auth_roles' => $claims->roles
            ]);
            
            return $next($request);
            
        } catch (Exception $e) {
            return response()->json(['error' => 'Authentication failed'], 401);
        }
    }
}
```

#### Plain PHP SAML Integration

```php
<?php
// Handle SAML SSO Response

require 'vendor/autoload.php';

use authlib\Auth\Auth\SamlAssertionValidator;
use authlib\Auth\Core\AuthorizationService;

// Load SAML configuration
$samlConfig = [
    'entity_id' => $_ENV['SAML_SP_ENTITY_ID'],
    'certificate_fingerprints' => explode(',', $_ENV['SAML_IDP_CERTIFICATE_FINGERPRINTS']),
    'issuer' => $_ENV['SAML_IDP_ISSUER'],
    'max_assertion_age' => 3600,
    'clock_skew' => 300
];

// Initialize components
$samlValidator = new SamlAssertionValidator($samlConfig);
$auth = new AuthorizationService($repository, $audit, $cache);

// Process SAML response
if ($_POST['SAMLResponse'] ?? false) {
    try {
        $claims = $samlValidator->validate($_POST['SAMLResponse']);
        
        // Store user session
        session_start();
        $_SESSION['user_id'] = $claims->sub;
        $_SESSION['groups'] = $claims->groups;
        $_SESSION['roles'] = $claims->roles;
        $_SESSION['saml_session_index'] = $claims->session_index;
        
        // Redirect to originally requested resource
        $returnUrl = $_SESSION['return_url'] ?? '/dashboard';
        unset($_SESSION['return_url']);
        
        header("Location: {$returnUrl}");
        exit;
        
    } catch (Exception $e) {
        error_log("SAML authentication failed: " . $e->getMessage());
        header('Location: /login?error=saml_auth_failed');
        exit;
    }
}

// Protect resource with SAML authentication
function requireSamlAuth(string $permission): void {
    session_start();
    
    $userId = $_SESSION['user_id'] ?? null;
    if (!$userId) {
        $_SESSION['return_url'] = $_SERVER['REQUEST_URI'];
        header('Location: /saml/login');
        exit;
    }
    
    global $auth;
    $hasPermission = $auth->hasPermission($userId, $permission, [
        'groups' => $_SESSION['groups'] ?? [],
        'roles' => $_SESSION['roles'] ?? [],
        'ip_address' => $_SERVER['REMOTE_ADDR']
    ]);
    
    if (!$hasPermission) {
        http_response_code(403);
        echo json_encode(['error' => 'Forbidden']);
        exit;
    }
}

// Usage in protected endpoint
requireSamlAuth('Orders.Edit');
echo json_encode(['message' => 'Access granted to edit orders']);
```

## Framework Integration

### Laravel Integration

#### 1. Register Service Provider

```php
// config/app.php
'providers' => [
    // ...
    authlib\Auth\Providers\LaravelServiceProvider::class,
],
```

#### 2. Publish Configuration

```bash
php artisan vendor:publish --provider="authlib\Auth\Providers\LaravelServiceProvider"
```

#### 3. Use Middleware

```php
// routes/web.php
Route::middleware(['auth.jwt:Orders.Edit'])->group(function () {
    Route::get('/orders', [OrderController::class, 'index']);
    Route::post('/orders', [OrderController::class, 'store'])->middleware('auth.jwt:Orders.Create');
    Route::delete('/orders/{id}', [OrderController::class, 'destroy'])->middleware('auth.jwt:Orders.Delete');
});
```

#### 4. Controller Usage

```php
<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use authlib\Auth\Contracts\AuthorizationServiceInterface;

class OrderController extends Controller
{
    public function __construct(
        private AuthorizationServiceInterface $auth
    ) {}

    public function show(Request $request, int $orderId)
    {
        $userId = $request->get('auth_user_id');
        
        // Check resource-specific permission
        $canView = $this->auth->hasPermission($userId, 'Orders.View', [
            'resource_id' => $orderId,
            'owner_id' => $this->getOrderOwner($orderId)
        ]);

        if (!$canView) {
            abort(403, 'Cannot view this order');
        }

        return response()->json($this->getOrder($orderId));
    }
}
```

### Slim Framework Integration

```php
<?php
use Slim\Factory\AppFactory;
use authlib\Auth\Middleware\HttpAuthorizationMiddleware;

$app = AppFactory::create();

// Add authorization middleware
$app->add(new HttpAuthorizationMiddleware($enforcer, 'Orders.Edit'));

$app->get('/orders', function ($request, $response) {
    $userId = $request->getAttribute('auth_user_id');
    $claims = $request->getAttribute('auth_claims');
    
    // User is authorized, proceed with business logic
    return $response->withJson(['orders' => $this->getOrdersForUser($userId)]);
});
```

### Plain PHP Integration

```php
<?php
// examples/plain-php/bootstrap.php shows complete setup

require 'vendor/autoload.php';

// Bootstrap AuthLib components (see examples/plain-php/bootstrap.php)
$auth = require __DIR__ . '/bootstrap.php';

// Extract JWT from request
$jwt = $_SERVER['HTTP_AUTHORIZATION'] 
    ? substr($_SERVER['HTTP_AUTHORIZATION'], 7) 
    : $_GET['token'] ?? '';

try {
    if ($enforcer->requirePermission($jwt, 'Orders.Edit')) {
        // User authorized - proceed
        echo json_encode(['status' => 'authorized']);
    } else {
        http_response_code(403);
        echo json_encode(['error' => 'Forbidden']);
    }
} catch (Exception $e) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized', 'message' => $e->getMessage()]);
}
```

## Database Schema

### Core Tables

```sql
-- Users and their direct role assignments
CREATE TABLE user_roles (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id VARCHAR(255) NOT NULL,
    role VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_user_role (user_id, role)
);

-- Users and their direct permission grants
CREATE TABLE user_permissions (
    id INT PRIMARY KEY AUTO_INCREMENT, 
    user_id VARCHAR(255) NOT NULL,
    permission VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_user_permission (user_id, permission)
);

-- Role-to-permission mappings
CREATE TABLE role_permissions (
    id INT PRIMARY KEY AUTO_INCREMENT,
    role VARCHAR(100) NOT NULL,
    permission VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_role_permission (role, permission)
);

-- AD Group to role mappings  
CREATE TABLE group_roles (
    id INT PRIMARY KEY AUTO_INCREMENT,
    group_id VARCHAR(500) NOT NULL, -- Full AD DN
    role VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_group_role (group_id, role)
);
```

### Sample Data Setup

```sql
-- Create application roles
INSERT INTO group_roles (group_id, role) VALUES
('CN=Sales_Team,OU=Groups,DC=company,DC=com', 'sales_user'),
('CN=Managers,OU=Groups,DC=company,DC=com', 'manager'),
('CN=Administrators,OU=Groups,DC=company,DC=com', 'admin');

-- Define role permissions
INSERT INTO role_permissions (role, permission) VALUES
('admin', 'Users.Create'),
('admin', 'Users.Edit'), 
('admin', 'Users.Delete'),
('admin', 'Orders.Create'),
('admin', 'Orders.Edit'),
('admin', 'Orders.Delete'),
('admin', 'Orders.View'),
('manager', 'Orders.Create'),
('manager', 'Orders.Edit'),
('manager', 'Orders.View'),
('manager', 'Reports.View'),
('sales_user', 'Orders.View'),
('sales_user', 'Profile.Edit');
```

## Configuration Reference

### Environment Variables

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `DB_HOST` | Yes | Database host | `localhost` |
| `DB_PORT` | No | Database port | `3306` |
| `DB_DATABASE` | Yes | Database name | `authlib_app` |
| `DB_USERNAME` | Yes | Database username | `app_user` |
| `DB_PASSWORD` | Yes | Database password | `secret123` |
| `OIDC_ISSUER` | Yes | OIDC issuer URL | `https://auth.company.com` |
| `OIDC_AUDIENCE` | Yes | Expected audience claim | `my-application` |
| `OIDC_JWKS_URI` | No | JWKS endpoint URL | `https://auth.company.com/.well-known/jwks` |
| `JWKS_PUBLIC_KEY` | No | Static public key (alternative to JWKS_URI) | `-----BEGIN CERTIFICATE-----\n...` |
| `AUTH_CACHE_TTL` | No | Permission cache TTL in seconds | `600` (10 minutes) |
| `TOKEN_MAX_AGE` | No | Maximum token age in seconds | `3600` (1 hour) |
| `LOG_LEVEL` | No | Logging level | `info` |
| `AUDIT_ENABLED` | No | Enable audit logging | `true` |

### JWKS Configuration

AuthLib supports multiple JWKS configuration methods:

#### Option 1: JWKS URI (Recommended)
```env
OIDC_JWKS_URI=https://your-pingfederate.example.com/.well-known/jwks
```

#### Option 2: Static Public Key
```env
JWKS_PUBLIC_KEY="-----BEGIN CERTIFICATE-----
MIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsF
...
-----END CERTIFICATE-----"
```

#### Option 3: File-based JWKS
```php
$validator = new OidcTokenValidator(
    issuer: $_ENV['OIDC_ISSUER'],
    audience: $_ENV['OIDC_AUDIENCE'], 
    jwksFilePath: '/path/to/jwks.json'
);
```

## Security & Best Practices

### Least Privilege Principle

1. **Start with minimal permissions** - Grant only the most restrictive access initially
2. **Use role hierarchy** - Create granular roles that can be combined
3. **Regular access reviews** - Periodically audit user permissions and remove unnecessary access

```php
// Good: Granular permissions
$repository->bindPermissionToRole('order_viewer', 'Orders.View');
$repository->bindPermissionToRole('order_editor', 'Orders.Edit'); 
$repository->bindPermissionToRole('order_manager', 'Orders.Delete');

// Better: Combine roles for complex permissions
$repository->bindRoleToUser('john@company.com', 'order_viewer');
$repository->bindRoleToUser('john@company.com', 'order_editor');
```

### Token Security

#### Short Token TTL
```env
# Keep tokens short-lived (15-60 minutes)
TOKEN_MAX_AGE=3600

# Use refresh tokens for longer sessions
REFRESH_TOKEN_TTL=86400
```

#### Key Rotation
```php
// Support multiple keys during rotation
$validator = new OidcTokenValidator(
    issuer: $_ENV['OIDC_ISSUER'],
    audience: $_ENV['OIDC_AUDIENCE'],
    jwksUri: $_ENV['OIDC_JWKS_URI'] // Automatically handles key rotation
);

// Clear JWKS cache during rotation
$validator->clearCache();
```

#### Token Validation Best Practices
```php
// Always validate all required claims
$validator = new OidcTokenValidator(
    issuer: $_ENV['OIDC_ISSUER'],        // Validate issuer
    audience: $_ENV['OIDC_AUDIENCE'],     // Validate audience  
    jwksUri: $_ENV['OIDC_JWKS_URI']
);

// Implement token blacklisting for logout
class TokenBlacklist {
    public function isBlacklisted(string $jti): bool {
        return $this->cache->has("blacklist:{$jti}");
    }
    
    public function blacklist(string $jti, int $exp): void {
        $ttl = $exp - time();
        $this->cache->set("blacklist:{$jti}", true, $ttl);
    }
}
```

### Caching Strategy

#### Permission Caching
```php
// Use PSR-6 cache for performance
$cachePool = new FilesystemAdapter('authlib', 600);
$cache = new PermissionCache($cachePool);

// Cache keys include all relevant context
// Format: "perm:{userId}:{permission}:{contextHash}"
$cacheKey = sprintf(
    'perm:%s:%s:%s',
    $userId,
    $permission, 
    md5(serialize($context))
);
```

#### Cache Invalidation
```php
// Clear cache when permissions change
class PermissionService {
    public function grantPermission(string $userId, string $permission): void {
        $this->repository->bindPermissionToUser($userId, $permission);
        
        // Invalidate related cache entries
        $this->cache->deleteByPrefix("perm:{$userId}");
        $this->audit->logPermissionGranted($userId, $permission);
    }
}
```

### Audit & Compliance

#### Comprehensive Logging
```php
use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use Monolog\Handler\SyslogHandler;

$logger = new Logger('authz');

// File logging for audit trails
$logger->pushHandler(new StreamHandler('/var/log/authz.log', Logger::INFO));

// Syslog for compliance (SOX, HIPAA, etc.)
$logger->pushHandler(new SyslogHandler('authlib', LOG_USER, Logger::WARNING));

$auditSink = new LoggerAuditSink($logger);
```

#### Audit Log Format
```json
{
  "timestamp": "2025-12-18T10:30:45Z",
  "event_type": "permission_check",
  "user_id": "john@company.com",
  "permission": "Orders.Edit",
  "result": "granted",
  "context": {
    "roles": ["manager"],
    "groups": ["CN=Sales_Team,OU=Groups,DC=company,DC=com"],
    "ip_address": "192.168.1.100",
    "user_agent": "Mozilla/5.0...",
    "cache_used": true
  }
}
```

### Policy Enforcement

#### Time-based Access
```php
// Restrict access to business hours
$timePolicy = PolicyEnforcer::timeBasedPolicy('09:00', '17:00', 'America/New_York');
$enforcer->addPolicy($timePolicy);
```

#### IP-based Access
```php
// Restrict to corporate network
$ipPolicy = PolicyEnforcer::ipBasedPolicy([
    '192.168.0.0/16',    // Internal network
    '10.0.0.0/8',        // VPN range
    '203.0.113.100'      // Specific external IP
]);
$enforcer->addPolicy($ipPolicy);
```

#### Resource Ownership
```php
// Users can only edit their own resources
$ownershipPolicy = PolicyEnforcer::resourceOwnershipPolicy('resource_id', 'owner_id');
$enforcer->addPolicy($ownershipPolicy);

// Usage
$hasPermission = $auth->hasPermission($userId, 'Orders.Edit', [
    'resource_id' => 'order_123',
    'owner_id' => 'john@company.com'  // Must match $userId for access
]);
```

## Advanced Usage

### Custom Claims Extractor

```php
use authlib\Auth\Contracts\ClaimsExtractorInterface;

class CustomClaimsExtractor implements ClaimsExtractorInterface
{
    public function extractClaims(object $payload): array
    {
        return [
            'user_id' => $payload->sub ?? $payload->email,
            'groups' => $this->parseAdGroups($payload->groups ?? []),
            'roles' => $payload->roles ?? [],
            'department' => $payload->department ?? null,
            'cost_center' => $payload->cost_center ?? null
        ];
    }
    
    private function parseAdGroups(array $groups): array
    {
        // Convert AD DNs to simple group names
        return array_map(function($group) {
            if (preg_match('/CN=([^,]+)/', $group, $matches)) {
                return $matches[1];
            }
            return $group;
        }, $groups);
    }
}
```

### Custom Policy Examples

```php
// Department-based access
$departmentPolicy = function(string $userId, string $permission, array $context): bool {
    $userDept = $context['department'] ?? null;
    $requiredDept = $context['required_department'] ?? null;
    
    return !$requiredDept || $userDept === $requiredDept;
};

// Multi-factor authentication requirement
$mfaPolicy = function(string $userId, string $permission, array $context): bool {
    $requiresMfa = str_contains($permission, 'Admin') || str_contains($permission, 'Delete');
    $hasMfa = $context['mfa_verified'] ?? false;
    
    return !$requiresMfa || $hasMfa;
};

$enforcer->addPolicies([$departmentPolicy, $mfaPolicy]);
```

## Limitations & Roadmap

### Current Limitations

#### 1. Group Overage Handling
When JWT tokens exceed size limits due to many group memberships:

**Current**: Basic group claim extraction
```php
// May fail with large group lists
$groups = $payload->groups ?? [];
```

**Mitigation Strategies**:
- Use group filtering at PingFederate level
- Implement group claim compression
- Use group lookup service instead of embedding all groups

**Planned**: Group overage handling in v2.0
```php
// Future: Support group lookup service
$groups = $claimsExtractor->resolveGroups($payload->group_refs ?? []);
```

#### 2. SAML Support
**Current Status**: OIDC/JWT only

**Planned**: SAML 2.0 assertion validation in v1.5
```php
// Future SAML support
$samlValidator = new SamlAssertionValidator($certPath);
$claims = $samlValidator->validateAssertion($samlResponse);
```

#### 3. Dynamic Role Assignment
**Current**: Static database role mappings only

**Planned**: Dynamic role resolution in v2.0
```php
// Future: Dynamic role assignment based on attributes
$roleResolver = new AttributeBasedRoleResolver([
    'department=Sales,level=Manager' => 'sales_manager',
    'department=IT,clearance=Secret' => 'it_admin'
]);
```

#### 4. Multi-Tenant Support
**Current**: Single-tenant design

**Planned**: Multi-tenant support in v2.0
```php
// Future: Tenant-aware permissions
$auth->hasPermission($userId, $permission, [
    'tenant_id' => 'company_a'
]);
```

### Performance Considerations

#### Database Optimization
```sql
-- Recommended indexes for large deployments
CREATE INDEX idx_user_roles_user ON user_roles(user_id);
CREATE INDEX idx_user_permissions_user ON user_permissions(user_id);
CREATE INDEX idx_role_permissions_role ON role_permissions(role);
CREATE INDEX idx_group_roles_group ON group_roles(group_id);

-- For high-volume audit logs
CREATE INDEX idx_audit_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_audit_user_id ON audit_logs(user_id);
```

#### Caching Recommendations
```php
// For high-traffic applications
$redisCache = new Redis();
$redisCache->connect('localhost', 6379);
$adapter = new RedisAdapter($redisCache);
$cache = new PermissionCache($adapter);

// Tune cache TTL based on security requirements
$cache->setDefaultTtl(300); // 5 minutes for high-security
// or
$cache->setDefaultTtl(1800); // 30 minutes for performance
```

## Troubleshooting

### Common Issues

#### 1. Token Validation Failures
```php
try {
    $payload = $validator->validate($token);
} catch (Exception $e) {
    // Log detailed error for debugging
    error_log("Token validation failed: " . $e->getMessage());
    
    // Common causes:
    // - Expired token (check exp claim)
    // - Wrong audience (check aud claim) 
    // - Invalid signature (check JWKS configuration)
    // - Clock skew (allow for small time differences)
}
```

#### 2. Permission Cache Issues
```php
// Clear cache when permissions aren't updating
$repository->clearCache();

// Debug cache keys
$cacheKey = sprintf('perm:%s:%s:%s', $userId, $permission, md5(serialize($context)));
if ($cache->has($cacheKey)) {
    $cachedResult = $cache->get($cacheKey);
    error_log("Cached permission result: " . json_encode($cachedResult));
}
```

#### 3. Group Mapping Problems
```sql
-- Verify group mappings
SELECT gr.group_id, gr.role, rp.permission 
FROM group_roles gr
JOIN role_permissions rp ON gr.role = rp.role
WHERE gr.group_id LIKE '%Sales%';

-- Check user's effective permissions  
SELECT DISTINCT rp.permission
FROM user_roles ur
JOIN role_permissions rp ON ur.role = rp.role  
WHERE ur.user_id = 'user@example.com'
UNION
SELECT permission FROM user_permissions 
WHERE user_id = 'user@example.com';
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
git clone https://github.com/authlib/rbac-authorization.git
cd rbac-authorization
composer install
cp .env.example .env
vendor/bin/phpunit
```

### Release Process

AuthLib follows [Semantic Versioning](https://semver.org/) for releases:

- **MAJOR** version for incompatible API changes
- **MINOR** version for backwards-compatible functionality additions
- **PATCH** version for backwards-compatible bug fixes

#### Creating a Release

1. **Update Version Numbers**
   ```bash
   # Update version in composer.json
   # Update version constants in source code if any
   ```

2. **Generate Changelog**
   ```bash
   # Install github-changelog-generator (one time setup)
   gem install github_changelog_generator
   
   # Generate changelog for new version
   github_changelog_generator --user authlib --project rbac-authorization --token YOUR_GITHUB_TOKEN
   ```

3. **Create Release Tag**
   ```bash
   git tag -a v1.2.3 -m "Release version 1.2.3"
   git push origin v1.2.3
   ```

4. **Publish to Packagist**
   - Releases are automatically published to Packagist when tags are pushed
   - Ensure your package is registered at https://packagist.org/packages/authlib/rbac-authorization

#### Packagist Setup

1. **Initial Registration**
   - Visit https://packagist.org/packages/submit
   - Submit your GitHub repository URL: `https://github.com/authlib/rbac-authorization`
   - Enable auto-updating via GitHub webhook

2. **Auto-Update Configuration**
   ```json
   {
     "name": "authlib/rbac-authorization",
     "repositories": [
       {
         "type": "vcs",
         "url": "https://github.com/authlib/rbac-authorization"
       }
     ]
   }
   ```

#### Version Management

```bash
# Check current version
git describe --tags --abbrev=0

# List all versions
git tag -l

# Create pre-release
git tag -a v1.3.0-beta.1 -m "Beta release 1.3.0-beta.1"

# Create stable release
git tag -a v1.3.0 -m "Release version 1.3.0

## Added
- New feature X
- Enhancement Y

## Fixed
- Bug Z
- Security issue A

## Changed
- Breaking change B (if major version)
"
```

### Changelog Maintenance

The project uses automated changelog generation with the following categories:

- **Added** for new features
- **Changed** for changes in existing functionality  
- **Deprecated** for soon-to-be removed features
- **Removed** for now removed features
- **Fixed** for any bug fixes
- **Security** for vulnerability fixes

#### Manual Changelog Updates

If you prefer manual changelog maintenance, follow this format:

```markdown
# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- New feature description

### Fixed
- Bug fix description

## [1.2.3] - 2025-12-19

### Added
- Comprehensive security practices implementation
- Enhanced JWT validation with clock skew handling
- Policy versioning with bindings hash tracking

### Fixed
- Input sanitization for all user inputs
- Cache TTL alignment with token expiration

### Security
- Default deny policy enforcement
- Prepared statements for all SQL queries
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Documentation**: [https://authlib.github.io/rbac-authorization](https://authlib.github.io/rbac-authorization)
- **Issues**: [GitHub Issues](https://github.com/authlib/rbac-authorization/issues)
- **Discussions**: [GitHub Discussions](https://github.com/authlib/rbac-authorization/discussions)
- **Security**: security@authlib.dev

---

**AuthLib RBAC Authorization Library** - Secure, scalable, and compliant authorization for modern PHP applications.