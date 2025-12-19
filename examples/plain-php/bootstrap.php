<?php

declare(strict_types=1);

/**
 * Bootstrap file for Plain PHP AuthLib example
 * 
 * This file sets up all the necessary components for the authorization system:
 * - Environment configuration
 * - Database connection
 * - Repository, audit sink, cache, and services
 * - Claims extractor and token validator
 * - Policy enforcer for permission checking
 */

// Load Composer autoloader
require __DIR__ . '/../../vendor/autoload.php';

// Load environment variables from .env file (if vlucas/phpdotenv is available)
if (class_exists('Dotenv\Dotenv')) {
    $dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/../../');
    $dotenv->safeLoad();
}

// Create PDO connection using DbConfig
$pdo = \authlib\Auth\Config\DbConfig::pdoFromEnv();

// Initialize repository for user bindings and permissions
$repo = new \authlib\Auth\Data\PdoBindingsRepository($pdo);

// Set up Monolog logger for audit trail
$logger = new \Monolog\Logger('authz');
$logger->pushHandler(new \Monolog\Handler\StreamHandler(__DIR__ . '/../../logs/authorization.log', \Monolog\Level::Info));
$logger->pushHandler(new \Monolog\Handler\StreamHandler('php://stdout', \Monolog\Level::Warning));

// Create audit sink for logging authorization events
$audit = new \authlib\Auth\Audit\LoggerAuditSink($logger);

// Initialize permission cache (using simple array cache or PSR-6 adapter)
$cache = new \authlib\Auth\Core\PermissionCache();

// Initialize claims extractor for JWT tokens
$claims = new \authlib\Auth\Auth\DefaultClaimsExtractor();

// Load JWKS (JSON Web Key Set) for token validation
// In production, this would typically be loaded from a JWKS endpoint or secure storage
$jwks = [];

// Check if JWKS file exists, otherwise use environment variable
$jwksFile = __DIR__ . '/jwks_public.pem';
if (file_exists($jwksFile)) {
    $jwks = ['kid-123' => file_get_contents($jwksFile)];
} elseif (getenv('JWKS_PUBLIC_KEY')) {
    $jwks = ['kid-123' => getenv('JWKS_PUBLIC_KEY')];
} else {
    // For demo purposes, create a placeholder
    $jwks = ['kid-123' => 'demo-public-key-content'];
}

// Initialize OIDC token validator
$validator = new \authlib\Auth\Auth\OidcTokenValidator(
    issuer: getenv('OIDC_ISSUER') ?: 'https://auth.example.com',
    audience: getenv('OIDC_AUDIENCE') ?: 'authlib-demo',
    jwksUri: null,
    jwksFilePath: null,
    staticJwks: $jwks
);

// First, create a temporary authorization service for the PolicyEnforcer
// We'll replace this reference later to avoid circular dependency
$tempAuth = new class implements \authlib\Auth\Contracts\AuthorizationServiceInterface {
    public function hasPermission(string $userId, string $permission, array $context = []): bool { return true; }
    public function hasAnyPermission(string $userId, array $permissions, array $context = []): bool { return true; }
    public function hasAllPermissions(string $userId, array $permissions, array $context = []): bool { return true; }
    public function hasRole(string $userId, string $role): bool { return true; }
    public function getAllPermissions(string $userId): array { return []; }
    public function getAllRoles(string $userId): array { return []; }
    public function authorize(string $token, string $permission, array $context = []): bool { return true; }
    public function userHasPermission(string $userId, array $groupIds, string $permission): bool { return true; }
};

// Create policy enforcer with temporary auth service
$enforcer = new \authlib\Auth\Core\PolicyEnforcer($validator, $claims, $tempAuth);

// Now create the real authorization service with all required dependencies
$auth = new \authlib\Auth\Core\AuthorizationService(
    repo: $repo,
    audit: $audit,
    cache: $cache,
    tokenValidator: $validator,
    claimsExtractor: $claims,
    policyEnforcer: $enforcer,
    auditSink: $audit
);

// Update the policy enforcer to use the real authorization service via reflection
// This is a workaround for the circular dependency
$reflection = new ReflectionClass($enforcer);
$authProperty = $reflection->getProperty('auth');
$authProperty->setAccessible(true);
$authProperty->setValue($enforcer, $auth);

// Example usage: Check permissions for 'Orders.Edit'
echo "=== AuthLib Bootstrap Complete ===\n";
echo "Testing permission check for 'Orders.Edit'\n\n";

// Extract JWT token from Authorization header
$jwt = '';
if (isset($_SERVER['HTTP_AUTHORIZATION']) && str_starts_with($_SERVER['HTTP_AUTHORIZATION'], 'Bearer ')) {
    $jwt = substr($_SERVER['HTTP_AUTHORIZATION'], 7);
} elseif (isset($_GET['token'])) {
    // Allow token via query parameter for testing
    $jwt = $_GET['token'];
}

try {
    if ($jwt) {
        // Check permission using JWT token
        if ($enforcer->requirePermission($jwt, 'Orders.Edit')) {
            echo "✅ SUCCESS: You have permission to edit orders.\n";
        } else {
            http_response_code(403);
            echo "❌ FORBIDDEN: You do not have permission to edit orders.\n";
        }
    } else {
        // Example with direct user ID (for testing without JWT)
        $testUserId = 'admin@example.com';
        
        echo "No JWT token provided. Testing with user ID: {$testUserId}\n";
        
        $hasPermission = $auth->hasPermission($testUserId, 'Orders.Edit', [
            'roles' => ['admin', 'manager'],
            'groups' => ['sales'],
            'cache_used' => false,
            'ip_address' => $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'CLI'
        ]);
        
        if ($hasPermission) {
            echo "✅ SUCCESS: User {$testUserId} can edit orders.\n";
        } else {
            echo "❌ DENIED: User {$testUserId} cannot edit orders.\n";
        }
        
        // Log the decision for audit trail
        $audit->logDecision($testUserId, 'Orders.Edit', $hasPermission, [
            'roles' => ['admin', 'manager'],
            'groups' => ['sales'],
            'cache_used' => false,
            'ip_address' => $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1',
            'resource' => 'orders',
            'action' => 'edit',
            'reason' => $hasPermission ? 'User has required permissions' : 'Insufficient permissions'
        ]);
    }
} catch (Exception $e) {
    http_response_code(500);
    echo "❌ ERROR: " . $e->getMessage() . "\n";
    
    // Log the error
    $audit->logSecurityEvent('authorization_error', [
        'error' => $e->getMessage(),
        'trace' => $e->getTraceAsString()
    ]);
}

echo "\n=== Additional Examples ===\n";

// Demonstrate other permission checks
$testPermissions = [
    'Orders.View',
    'Orders.Create',
    'Orders.Delete',
    'Products.Edit',
    'Users.Manage'
];

$testUserId = 'admin@example.com';

foreach ($testPermissions as $permission) {
    try {
        $hasPermission = $auth->hasPermission($testUserId, $permission, [
            'roles' => ['admin'],
            'cache_used' => true // Simulate cache usage
        ]);
        
        $status = $hasPermission ? '✅ GRANTED' : '❌ DENIED';
        echo "{$status}: {$permission}\n";
        
        // Log each decision
        if ($hasPermission) {
            $audit->logPermissionGranted($testUserId, $permission, [
                'roles' => ['admin'],
                'cache_used' => true
            ]);
        } else {
            $audit->logPermissionDenied($testUserId, $permission, [
                'roles' => ['admin'],
                'cache_used' => true,
                'reason' => 'Insufficient role privileges'
            ]);
        }
        
    } catch (Exception $e) {
        echo "❌ ERROR checking {$permission}: " . $e->getMessage() . "\n";
    }
}

// Return the authorization service for use in other files
return $auth;