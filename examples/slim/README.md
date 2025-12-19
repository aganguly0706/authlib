# Slim Framework Integration Example

This example demonstrates how to integrate AuthLib RBAC Authorization with Slim Framework 4.

## Complete Application Setup

### 1. Dependencies (composer.json)

```json
{
    "require": {
        "slim/slim": "^4.12",
        "slim/psr7": "^1.6",
        "authlib/rbac-authorization": "^1.0",
        "monolog/monolog": "^3.5",
        "vlucas/phpdotenv": "^5.5"
    }
}
```

### 2. Bootstrap File (bootstrap.php)

```php
<?php
require_once __DIR__ . '/../vendor/autoload.php';

use authlib\Auth\Core\AuthorizationService;
use authlib\Auth\Core\PolicyEnforcer;
use authlib\Auth\Core\PermissionCache;
use authlib\Auth\Data\PdoBindingsRepository;
use authlib\Auth\Auth\OidcTokenValidator;
use authlib\Auth\Auth\DefaultClaimsExtractor;
use authlib\Auth\Audit\LoggerAuditSink;
use authlib\Auth\Config\DbConfig;
use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use Dotenv\Dotenv;

// Load environment variables
$dotenv = Dotenv::createImmutable(__DIR__ . '/../');
$dotenv->load();

// Database connection
$pdo = DbConfig::pdoFromEnv();

// Components setup
$repository = new PdoBindingsRepository($pdo);
$cache = new PermissionCache();

// Audit logging
$logger = new Logger('authlib');
$logger->pushHandler(new StreamHandler(__DIR__ . '/../logs/auth.log', Logger::INFO));
$auditSink = new LoggerAuditSink($logger);

// Authorization service
$authService = new AuthorizationService($repository, $auditSink, $cache);

// OIDC token validator
$tokenValidator = new OidcTokenValidator(
    issuer: $_ENV['OIDC_ISSUER'],
    audience: $_ENV['OIDC_AUDIENCE'],
    jwksUri: $_ENV['OIDC_JWKS_URI']
);

$claimsExtractor = new DefaultClaimsExtractor();

// Policy enforcer with token validation
$enforcer = new PolicyEnforcer(
    authService: $authService,
    tokenValidator: $tokenValidator,
    claimsExtractor: $claimsExtractor
);

return $enforcer;
```

### 3. Main Application (public/index.php)

```php
<?php
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Factory\AppFactory;
use Slim\Middleware\ErrorMiddleware;
use authlib\Auth\Middleware\HttpAuthorizationMiddleware;

require_once __DIR__ . '/../bootstrap.php';

// Create Slim app
$app = AppFactory::create();

// Get the PolicyEnforcer from bootstrap
$enforcer = require __DIR__ . '/../bootstrap.php';

// Error handling middleware
$errorMiddleware = $app->addErrorMiddleware(true, true, true);
$errorMiddleware->setDefaultErrorHandler(function (Request $request, Throwable $exception) {
    $response = new \Slim\Psr7\Response();
    $response->getBody()->write(json_encode([
        'error' => 'Internal Server Error',
        'message' => $exception->getMessage()
    ]));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
});

// CORS middleware (if needed)
$app->add(function (Request $request, \Psr\Http\Server\RequestHandlerInterface $handler): Response {
    $response = $handler->handle($request);
    return $response
        ->withHeader('Access-Control-Allow-Origin', '*')
        ->withHeader('Access-Control-Allow-Headers', 'X-Requested-With, Content-Type, Accept, Origin, Authorization')
        ->withHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
});

// ================================
// PUBLIC ROUTES (No Authorization)
// ================================

$app->get('/health', function (Request $request, Response $response) {
    $data = [
        'status' => 'healthy',
        'timestamp' => gmdate('c'),
        'version' => '1.0.0'
    ];
    $response->getBody()->write(json_encode($data));
    return $response->withHeader('Content-Type', 'application/json');
});

// ================================
// PROTECTED ROUTES WITH AUTHORIZATION
// ================================

// Orders API - View permission required
$app->group('/api/orders', function ($group) use ($enforcer) {
    
    // List orders - requires Orders.View permission
    $group->get('', function (Request $request, Response $response) {
        // Extract user info added by middleware
        $userId = $request->getAttribute('auth_user_id');
        $userRoles = $request->getAttribute('auth_roles', []);
        
        // Business logic - fetch orders based on user permissions
        $orders = getOrdersForUser($userId, $userRoles);
        
        $response->getBody()->write(json_encode([
            'orders' => $orders,
            'total' => count($orders),
            'user_id' => $userId,
            'permissions' => ['Orders.View']
        ]));
        
        return $response->withHeader('Content-Type', 'application/json');
    });
    
    // Get specific order - requires Orders.View permission
    $group->get('/{id:[0-9]+}', function (Request $request, Response $response, array $args) {
        $orderId = (int) $args['id'];
        $userId = $request->getAttribute('auth_user_id');
        
        // Check if user can view this specific order (resource-level permission)
        $order = getOrderById($orderId);
        if (!$order) {
            $response->getBody()->write(json_encode(['error' => 'Order not found']));
            return $response->withStatus(404)->withHeader('Content-Type', 'application/json');
        }
        
        // Additional business logic for order ownership check could go here
        if (!canUserAccessOrder($userId, $order)) {
            $response->getBody()->write(json_encode(['error' => 'Access denied to this order']));
            return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
        }
        
        $response->getBody()->write(json_encode(['order' => $order]));
        return $response->withHeader('Content-Type', 'application/json');
    });
    
})->add(new HttpAuthorizationMiddleware($enforcer, 'Orders.View'));

// Orders Management API - Edit permission required
$app->group('/api/orders', function ($group) use ($enforcer) {
    
    // Create order - requires Orders.Create permission
    $group->post('', function (Request $request, Response $response) {
        $userId = $request->getAttribute('auth_user_id');
        $data = json_decode($request->getBody()->getContents(), true);
        
        // Validate input
        if (!$data || !isset($data['customer_id'], $data['items'])) {
            $response->getBody()->write(json_encode(['error' => 'Invalid order data']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }
        
        // Create order
        $orderId = createOrder($userId, $data);
        
        $response->getBody()->write(json_encode([
            'message' => 'Order created successfully',
            'order_id' => $orderId,
            'created_by' => $userId
        ]));
        
        return $response->withStatus(201)->withHeader('Content-Type', 'application/json');
    });
    
    // Update order - requires Orders.Edit permission
    $group->put('/{id:[0-9]+}', function (Request $request, Response $response, array $args) {
        $orderId = (int) $args['id'];
        $userId = $request->getAttribute('auth_user_id');
        $data = json_decode($request->getBody()->getContents(), true);
        
        // Check if order exists and user can edit it
        $order = getOrderById($orderId);
        if (!$order) {
            $response->getBody()->write(json_encode(['error' => 'Order not found']));
            return $response->withStatus(404)->withHeader('Content-Type', 'application/json');
        }
        
        // Update order
        $updated = updateOrder($orderId, $userId, $data);
        
        if ($updated) {
            $response->getBody()->write(json_encode([
                'message' => 'Order updated successfully',
                'order_id' => $orderId,
                'updated_by' => $userId
            ]));
        } else {
            $response->getBody()->write(json_encode(['error' => 'Failed to update order']));
            return $response->withStatus(400);
        }
        
        return $response->withHeader('Content-Type', 'application/json');
    });
    
})->add(new HttpAuthorizationMiddleware($enforcer, 'Orders.Edit'));

// Admin-only routes - requires Admin permissions
$app->group('/api/admin', function ($group) use ($enforcer) {
    
    // Delete orders - requires Orders.Delete permission
    $group->delete('/orders/{id:[0-9]+}', function (Request $request, Response $response, array $args) {
        $orderId = (int) $args['id'];
        $userId = $request->getAttribute('auth_user_id');
        
        $deleted = deleteOrder($orderId, $userId);
        
        if ($deleted) {
            $response->getBody()->write(json_encode([
                'message' => 'Order deleted successfully',
                'order_id' => $orderId,
                'deleted_by' => $userId
            ]));
        } else {
            $response->getBody()->write(json_encode(['error' => 'Failed to delete order']));
            return $response->withStatus(400);
        }
        
        return $response->withHeader('Content-Type', 'application/json');
    });
    
    // User management - requires Users.Manage permission
    $group->get('/users', function (Request $request, Response $response) {
        $users = getAllUsers();
        $response->getBody()->write(json_encode(['users' => $users]));
        return $response->withHeader('Content-Type', 'application/json');
    });
    
    // System stats - requires Admin.View permission
    $group->get('/stats', function (Request $request, Response $response) {
        $stats = [
            'total_orders' => getTotalOrders(),
            'active_users' => getActiveUserCount(),
            'system_health' => 'good'
        ];
        $response->getBody()->write(json_encode($stats));
        return $response->withHeader('Content-Type', 'application/json');
    });
    
})->add(new HttpAuthorizationMiddleware($enforcer, 'Admin.Manage'));

// ================================
// BUSINESS LOGIC FUNCTIONS
// ================================

function getOrdersForUser(string $userId, array $roles): array
{
    // Mock implementation - replace with real database queries
    $allOrders = [
        ['id' => 1, 'customer' => 'John Doe', 'total' => 150.00, 'owner' => $userId],
        ['id' => 2, 'customer' => 'Jane Smith', 'total' => 275.50, 'owner' => 'other@company.com'],
        ['id' => 3, 'customer' => 'Bob Wilson', 'total' => 89.99, 'owner' => $userId]
    ];
    
    // Filter orders based on roles (managers see all, others see only their own)
    if (in_array('manager', $roles) || in_array('admin', $roles)) {
        return $allOrders;
    }
    
    // Regular users see only their own orders
    return array_filter($allOrders, fn($order) => $order['owner'] === $userId);
}

function getOrderById(int $orderId): ?array
{
    // Mock implementation
    $orders = [
        1 => ['id' => 1, 'customer' => 'John Doe', 'total' => 150.00, 'owner' => 'john@company.com'],
        2 => ['id' => 2, 'customer' => 'Jane Smith', 'total' => 275.50, 'owner' => 'jane@company.com'],
    ];
    
    return $orders[$orderId] ?? null;
}

function canUserAccessOrder(string $userId, array $order): bool
{
    // Business rule: users can access their own orders, managers can access all
    return $order['owner'] === $userId;
    // Note: Role-based access is already handled by the middleware
}

function createOrder(string $userId, array $data): int
{
    // Mock implementation - would insert into database
    return rand(1000, 9999);
}

function updateOrder(int $orderId, string $userId, array $data): bool
{
    // Mock implementation - would update database
    return true;
}

function deleteOrder(int $orderId, string $userId): bool
{
    // Mock implementation - would delete from database
    return true;
}

function getAllUsers(): array
{
    // Mock implementation
    return [
        ['id' => 'john@company.com', 'name' => 'John Doe', 'role' => 'sales_user'],
        ['id' => 'jane@company.com', 'name' => 'Jane Smith', 'role' => 'manager'],
    ];
}

function getTotalOrders(): int { return 1247; }
function getActiveUserCount(): int { return 89; }

// ================================
// RUN THE APPLICATION
// ================================

$app->run();
```

### 4. Environment Configuration (.env)

```env
# Database Configuration
DB_HOST=localhost
DB_PORT=3306
DB_DATABASE=authlib_app
DB_USERNAME=app_user
DB_PASSWORD=secret123

# OIDC Configuration
OIDC_ISSUER=https://your-pingfederate.company.com
OIDC_AUDIENCE=slim-orders-api
OIDC_JWKS_URI=https://your-pingfederate.company.com/.well-known/jwks

# Security Settings
AUTH_CACHE_TTL=600
TOKEN_MAX_AGE=3600
LOG_LEVEL=info
```

### 5. Usage Examples

#### Making Authenticated Requests

```bash
# Get JWT token from your OIDC provider first
export TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..."

# View orders (requires Orders.View permission)
curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:8080/api/orders

# Create order (requires Orders.Edit permission)  
curl -X POST \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"customer_id": 123, "items": [{"id": 1, "qty": 2}]}' \
     http://localhost:8080/api/orders

# Admin functions (requires Admin.Manage permission)
curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:8080/api/admin/stats
```

### 6. Advanced Middleware Configuration

```php
// Custom middleware with additional context
$app->add(function (Request $request, RequestHandlerInterface $handler) use ($enforcer) {
    $middleware = new HttpAuthorizationMiddleware($enforcer, 'Orders.View');
    
    // Add custom context for policy evaluation
    $context = [
        'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
        'request_time' => time(),
        'resource_type' => 'order'
    ];
    
    $request = $request->withAttribute('auth_context', $context);
    
    return $middleware->process($request, $handler);
});

// Route-specific permissions with dynamic context
$app->get('/api/orders/{id:[0-9]+}', function (Request $request, Response $response, array $args) {
    $orderId = $args['id'];
    $userId = $request->getAttribute('auth_user_id');
    
    // Use enforcer directly for resource-specific checks
    global $enforcer;
    
    $hasAccess = $enforcer->enforcePermission($userId, 'Orders.View', [
        'resource_id' => $orderId,
        'action' => 'view',
        'ip_address' => $_SERVER['REMOTE_ADDR']
    ]);
    
    if (!$hasAccess) {
        $response->getBody()->write(json_encode(['error' => 'Access denied to this resource']));
        return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
    }
    
    // Continue with business logic...
    $order = getOrderById((int) $orderId);
    $response->getBody()->write(json_encode(['order' => $order]));
    return $response->withHeader('Content-Type', 'application/json');
});
```

## Key Features Demonstrated

- ✅ **Route-level authorization** with different permission requirements
- ✅ **Grouped routes** with shared middleware
- ✅ **JWT token validation** via Authorization header
- ✅ **User context extraction** from validated tokens
- ✅ **Resource-level permissions** for specific orders
- ✅ **Role-based data filtering** (managers see all, users see own)
- ✅ **Error handling** for unauthorized access
- ✅ **Comprehensive API structure** with CRUD operations

This example shows how to build a complete API with AuthLib's security features integrated into Slim Framework!