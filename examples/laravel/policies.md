# Policy Configuration Guide

AuthLib includes a flexible policy enforcement engine that allows you to implement fine-grained authorization rules beyond simple role-based access control.

## Overview

Policies are callable functions that receive the user ID, permission being checked, and context data. They return `true` to allow access or `false` to deny it.

## Built-in Policy Types

### Time-based Policies

Restrict access based on time of day:

```php
use authlib\Auth\Core\PolicyEnforcer;

$policyEnforcer = new PolicyEnforcer([
    // Business hours only (9 AM to 6 PM Eastern Time)
    PolicyEnforcer::timeBasedPolicy('09:00', '18:00', 'America/New_York'),
]);
```

### IP-based Policies

Restrict access based on client IP address:

```php
$policyEnforcer = new PolicyEnforcer([
    // Only allow access from specific IPs or CIDR blocks
    PolicyEnforcer::ipBasedPolicy([
        '192.168.1.0/24',
        '10.0.0.100',
        '203.0.113.0/24',
    ]),
]);
```

### Resource Ownership Policies

Allow users to access only resources they own:

```php
$policyEnforcer = new PolicyEnforcer([
    // Users can only edit their own documents
    PolicyEnforcer::resourceOwnershipPolicy('resource_id', 'owner_id'),
]);
```

## Custom Policies

You can create custom policies as callable functions:

```php
// Custom policy: Only allow access during weekdays
$weekdayPolicy = function (string $userId, string $permission, array $context): bool {
    $dayOfWeek = (int) date('w'); // 0 = Sunday, 6 = Saturday
    return $dayOfWeek >= 1 && $dayOfWeek <= 5; // Monday to Friday
};

// Custom policy: Require MFA for admin operations
$mfaPolicy = function (string $userId, string $permission, array $context): bool {
    if (str_starts_with($permission, 'admin.')) {
        return ($context['mfa_verified'] ?? false) === true;
    }
    return true; // Non-admin operations don't require MFA
};

// Custom policy: Rate limiting based on user tier
$rateLimitPolicy = function (string $userId, string $permission, array $context): bool {
    $userTier = $context['user_tier'] ?? 'basic';
    $currentHour = (int) date('H');
    $requestCount = $context['hourly_request_count'] ?? 0;
    
    $limits = [
        'basic' => 100,
        'premium' => 1000,
        'enterprise' => 10000,
    ];
    
    return $requestCount < ($limits[$userTier] ?? 100);
};

$policyEnforcer = new PolicyEnforcer([
    $weekdayPolicy,
    $mfaPolicy,
    $rateLimitPolicy,
]);
```

## Policy Composition

Policies can be combined and modified at runtime:

```php
$policyEnforcer = new PolicyEnforcer();

// Add policies individually
$policyEnforcer->addPolicy($weekdayPolicy);
$policyEnforcer->addPolicy($mfaPolicy);

// Add multiple policies at once
$policyEnforcer->addPolicies([
    PolicyEnforcer::timeBasedPolicy('08:00', '20:00'),
    PolicyEnforcer::ipBasedPolicy(['192.168.0.0/16']),
]);

// Clear all policies
$policyEnforcer->clearPolicies();
```

## Advanced Policy Examples

### Department-based Access

```php
$departmentPolicy = function (string $userId, string $permission, array $context): bool {
    $userDepartment = $context['token_claims']['department'] ?? null;
    $resourceDepartment = $context['resource_department'] ?? null;
    
    // If permission is department-specific, check department match
    if (str_contains($permission, 'department.') && $resourceDepartment) {
        return $userDepartment === $resourceDepartment;
    }
    
    return true;
};
```

### Geographic Restrictions

```php
$geoPolicy = function (string $userId, string $permission, array $context): bool {
    $userCountry = $context['geo_country'] ?? null;
    $restrictedCountries = ['CN', 'IR', 'KP']; // Example restricted countries
    
    if (str_contains($permission, 'export.')) {
        return !in_array($userCountry, $restrictedCountries);
    }
    
    return true;
};
```

### Conditional MFA Requirements

```php
$conditionalMfaPolicy = function (string $userId, string $permission, array $context): bool {
    $isHighRisk = (
        str_contains($permission, 'admin.') ||
        str_contains($permission, 'delete.') ||
        str_contains($permission, 'financial.')
    );
    
    $isNewLocation = $context['new_location'] ?? false;
    $mfaVerified = $context['mfa_verified'] ?? false;
    
    if ($isHighRisk || $isNewLocation) {
        return $mfaVerified;
    }
    
    return true;
};
```

### Dynamic Policies Based on User Attributes

```php
$dynamicPolicy = function (string $userId, string $permission, array $context): bool {
    $userClaims = $context['token_claims'] ?? [];
    $userLevel = $userClaims['user_level'] ?? 1;
    $accountAge = $userClaims['account_age_days'] ?? 0;
    
    // New users (< 7 days) have restricted access
    if ($accountAge < 7) {
        $allowedPermissions = ['profile.read', 'profile.update', 'content.read'];
        return in_array($permission, $allowedPermissions);
    }
    
    // Level-based permissions
    $levelPermissions = [
        1 => ['profile.', 'content.read'],
        2 => ['profile.', 'content.read', 'content.create'],
        3 => ['profile.', 'content.', 'user.read'],
        4 => ['*'], // Admin level - all permissions
    ];
    
    $allowed = $levelPermissions[$userLevel] ?? [];
    
    foreach ($allowed as $pattern) {
        if ($pattern === '*' || str_starts_with($permission, $pattern)) {
            return true;
        }
    }
    
    return false;
};
```

## Policy Testing

Policies should be thoroughly tested:

```php
// Test time-based policy
$timePolicy = PolicyEnforcer::timeBasedPolicy('09:00', '17:00', 'UTC');

// Mock current time for testing
$context = ['current_time' => '2023-12-18 10:00:00'];
$result = $timePolicy('user123', 'read', $context);
assert($result === true);

$context = ['current_time' => '2023-12-18 18:00:00'];
$result = $timePolicy('user123', 'read', $context);
assert($result === false);
```

## Performance Considerations

1. **Policy Order**: Place most restrictive policies first to fail fast
2. **Caching**: Cache policy results when appropriate
3. **Complexity**: Keep policies simple and focused on single concerns
4. **Exception Handling**: Policies that throw exceptions will deny access

## Integration with Laravel

```php
// In a service provider
$this->app->singleton(PolicyEnforcer::class, function ($app) {
    return new PolicyEnforcer([
        PolicyEnforcer::timeBasedPolicy('09:00', '17:00'),
        PolicyEnforcer::ipBasedPolicy(config('auth.allowed_ips', [])),
        // Add custom policies here
    ]);
});
```

## Integration with Dependency Injection

```php
class AuthorizationService
{
    public function __construct(
        TokenValidatorInterface $tokenValidator,
        ClaimsExtractorInterface $claimsExtractor,
        BindingsRepositoryInterface $bindingsRepository,
        PolicyEnforcer $policyEnforcer
    ) {
        $this->policyEnforcer = $policyEnforcer;
        // ...
    }
}
```

## Best Practices

1. **Single Responsibility**: Each policy should check one specific condition
2. **Fail Secure**: Policies should default to denying access on errors
3. **Documentation**: Document policy behavior and requirements
4. **Testing**: Write unit tests for all custom policies
5. **Monitoring**: Log policy decisions for auditing
6. **Performance**: Avoid expensive operations in frequently-called policies