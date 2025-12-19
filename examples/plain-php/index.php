<?php

declare(strict_types=1);

use authlib\Auth\Contracts\AuthorizationServiceInterface;

/**
 * Plain PHP example demonstrating AuthLib usage
 */

// Bootstrap the AuthLib service
/** @var AuthorizationServiceInterface $authorizationService */
$authorizationService = require_once __DIR__ . '/bootstrap.php';

// Example 1: Basic permission check
echo "=== Example 1: Basic Permission Check ===\n";

$userId = 'admin@example.com';
$permission = 'user.create';

try {
    $hasPermission = $authorizationService->hasPermission($userId, $permission);
    echo "User {$userId} has permission '{$permission}': " . ($hasPermission ? 'YES' : 'NO') . "\n";
} catch (Exception $e) {
    echo "Error checking permission: " . $e->getMessage() . "\n";
}

// Example 2: Token-based authorization
echo "\n=== Example 2: Token-based Authorization ===\n";

// This would be a real JWT token in practice
$token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...'; // Example JWT token

try {
    $authorized = $authorizationService->authorize($token, 'content.read', [
        'ip_address' => '192.168.1.100',
        'resource_id' => 'article_123',
    ]);
    
    echo "Token authorization for 'content.read': " . ($authorized ? 'GRANTED' : 'DENIED') . "\n";
} catch (Exception $e) {
    echo "Token validation failed: " . $e->getMessage() . "\n";
}

// Example 3: Multiple permission check
echo "\n=== Example 3: Multiple Permission Check ===\n";

$permissions = ['content.read', 'content.update', 'content.delete'];

try {
    $hasAny = $authorizationService->hasAnyPermission($userId, $permissions);
    $hasAll = $authorizationService->hasAllPermissions($userId, $permissions);
    
    echo "User {$userId} has ANY of the permissions: " . ($hasAny ? 'YES' : 'NO') . "\n";
    echo "User {$userId} has ALL of the permissions: " . ($hasAll ? 'YES' : 'NO') . "\n";
} catch (Exception $e) {
    echo "Error checking permissions: " . $e->getMessage() . "\n";
}

// Example 4: Role check
echo "\n=== Example 4: Role Check ===\n";

try {
    $hasRole = $authorizationService->hasRole($userId, 'admin');
    echo "User {$userId} has role 'admin': " . ($hasRole ? 'YES' : 'NO') . "\n";
    
    $allRoles = $authorizationService->getAllRoles($userId);
    echo "All roles for {$userId}: " . implode(', ', $allRoles) . "\n";
    
    $allPermissions = $authorizationService->getAllPermissions($userId);
    echo "All permissions for {$userId}: " . implode(', ', $allPermissions) . "\n";
} catch (Exception $e) {
    echo "Error checking role: " . $e->getMessage() . "\n";
}

// Example 5: Context-aware authorization
echo "\n=== Example 5: Context-aware Authorization ===\n";

$context = [
    'ip_address' => '192.168.1.100',
    'user_agent' => 'Mozilla/5.0...',
    'resource_id' => 'document_456',
    'owner_id' => 'alice@example.com',
];

try {
    $authorized = $authorizationService->hasPermission('alice@example.com', 'document.edit', $context);
    echo "User alice@example.com can edit document_456: " . ($authorized ? 'YES' : 'NO') . "\n";
} catch (Exception $e) {
    echo "Error in context-aware check: " . $e->getMessage() . "\n";
}

echo "\n=== Examples Complete ===\n";