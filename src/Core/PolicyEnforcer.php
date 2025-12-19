<?php

declare(strict_types=1);

namespace authlib\Auth\Core;

use authlib\Auth\Contracts\TokenValidatorInterface;
use authlib\Auth\Contracts\ClaimsExtractorInterface;
use authlib\Auth\Contracts\AuthorizationServiceInterface;

/**
 * Policy enforcement engine for fine-grained authorization
 * Implements default deny with explicit per-function policies
 * Supports multiple token validators (OIDC, SAML, etc.)
 */
class PolicyEnforcer
{
    private array $policies = [];
    private array $functionPolicies = []; // Per-function policy overrides
    private bool $defaultDeny = true; // Explicit default deny
    
    /** @var TokenValidatorInterface[] */
    private array $validators = [];

    public function __construct(
        private readonly AuthorizationServiceInterface $authService,
        private readonly ClaimsExtractorInterface $claimsExtractor,
        array $policies = []
    ) {
        $this->policies = $policies;
    }

    /**
     * Add a token validator (OIDC, SAML, etc.)
     */
    public function addTokenValidator(TokenValidatorInterface $validator): void
    {
        $this->validators[] = $validator;
    }

    /**
     * Set multiple token validators
     */
    public function setTokenValidators(array $validators): void
    {
        $this->validators = [];
        foreach ($validators as $validator) {
            if ($validator instanceof TokenValidatorInterface) {
                $this->validators[] = $validator;
            }
        }
    }

    /**
     * Validate token using any of the configured validators
     */
    private function validateToken(string $token): \stdClass
    {
        if (empty($this->validators)) {
            throw new \Exception('No token validators configured');
        }

        $lastException = null;
        
        foreach ($this->validators as $validator) {
            try {
                return $validator->validate($token);
            } catch (\Exception $e) {
                $lastException = $e;
                continue;
            }
        }

        throw new \Exception('Token validation failed with all validators: ' . ($lastException?->getMessage() ?? 'Unknown error'));
    }

    /**
     * Enforce permission with token validation and policy checks
     */
    public function enforcePermission(string $token, string $permission, array $context = []): bool
    {
        try {
            // Validate token first
            $claims = $this->validateToken($token);
            
            // Extract user information
            $userId = $this->claimsExtractor->extractUserId($claims);
            $groups = $this->claimsExtractor->extractGroups($claims);
            $roles = $this->claimsExtractor->extractRoles($claims);
            
            // Add token claims to context for policy evaluation
            $context = array_merge($context, [
                'user_id' => $userId,
                'groups' => $groups,
                'roles' => $roles,
                'token_claims' => $claims,
                'token_type' => $this->detectTokenType($claims)
            ]);
            
            // Check base authorization first
            if (!$this->authService->userHasPermission($userId, $groups, $permission)) {
                return false;
            }
            
            // Then enforce policies
            return $this->enforce($userId, $permission, $context);
            
        } catch (\Exception) {
            return false; // Default deny on any error
        }
    }

    /**
     * Require a specific permission for the given token (throws on failure)
     */
    public function requirePermission(string $token, string $permission, array $context = []): bool
    {
        // Validate token first
        $claims = $this->validateToken($token);
        
        // Extract user information
        $userId = $this->claimsExtractor->extractUserId($claims);
        $groups = $this->claimsExtractor->extractGroups($claims);
        
        // Check authorization
        if (!$this->authService->userHasPermission($userId, $groups, $permission)) {
            throw new \Exception("User {$userId} does not have permission: {$permission}");
        }
        
        // Add token claims to context
        $context = array_merge($context, [
            'user_id' => $userId,
            'groups' => $groups,
            'roles' => $this->claimsExtractor->extractRoles($claims),
            'token_claims' => $claims,
            'token_type' => $this->detectTokenType($claims)
        ]);
        
        // Enforce policies
        if (!$this->enforce($userId, $permission, $context)) {
            throw new \Exception("Access denied by policy for user {$userId}, permission: {$permission}");
        }
        
        return true;
    }

    /**
     * Extract claims from a token without enforcement
     */
    public function getClaims(string $token): ?\stdClass
    {
        try {
            return $this->validateToken($token);
        } catch (\Exception) {
            return null;
        }
    }

    /**
     * Detect token type from claims structure
     */
    private function detectTokenType(\stdClass $claims): string
    {
        // SAML assertions have name_id_format or session_index
        if (isset($claims->name_id_format) || isset($claims->session_index)) {
            return 'saml';
        }
        
        // OIDC tokens typically have specific claims
        if (isset($claims->iss) && isset($claims->aud) && isset($claims->exp)) {
            return 'oidc';
        }
        
        return 'unknown';
    }

    /**
     * Enforce policies for a permission check - DEFAULT DENY
     * All policies must pass for access to be granted
     *
     * @param string $userId The user ID
     * @param string $permission The permission being checked
     * @param array<string, mixed> $context Additional context for policy evaluation
     * @return bool True if all policies pass, false otherwise (DEFAULT DENY)
     */
    public function enforce(string $userId, string $permission, array $context = []): bool
    {
        // Default deny - no policies means no access
        if (empty($this->policies) && !isset($this->functionPolicies[$permission])) {
            return false;
        }

        // Check function-specific policies first
        if (isset($this->functionPolicies[$permission])) {
            foreach ($this->functionPolicies[$permission] as $policy) {
                if (!$this->evaluatePolicy($policy, $userId, $permission, $context)) {
                    return false; // Default deny on any policy failure
                }
            }
        }

        // Check global policies
        foreach ($this->policies as $policy) {
            if (!$this->evaluatePolicy($policy, $userId, $permission, $context)) {
                return false; // Default deny on any policy failure
            }
        }

        return true;
    }

    /**
     * Create a token type policy that only allows specific authentication methods
     *
     * @param array<string> $allowedTypes Allowed token types ('oidc', 'saml')
     * @return callable
     */
    public static function tokenTypePolicy(array $allowedTypes): callable
    {
        return function (string $userId, string $permission, array $context) use ($allowedTypes) {
            $tokenType = $context['token_type'] ?? 'unknown';
            return in_array($tokenType, $allowedTypes, true);
        };
    }

    /**
     * Create a SAML-specific policy that validates SAML assertion attributes
     *
     * @param array<string> $requiredAttributes Required SAML attribute names
     * @param array<string, string> $attributeValues Required attribute values (name => value)
     * @return callable
     */
    public static function samlAttributePolicy(array $requiredAttributes = [], array $attributeValues = []): callable
    {
        return function (string $userId, string $permission, array $context) use ($requiredAttributes, $attributeValues) {
            $claims = $context['token_claims'] ?? null;
            
            if (!$claims || ($context['token_type'] ?? '') !== 'saml') {
                return false;
            }

            // Check required attributes exist
            foreach ($requiredAttributes as $attribute) {
                if (!isset($claims->{$attribute})) {
                    return false;
                }
            }

            // Check specific attribute values
            foreach ($attributeValues as $attribute => $expectedValue) {
                $actualValue = $claims->{$attribute} ?? null;
                if ($actualValue !== $expectedValue) {
                    return false;
                }
            }

            return true;
        };
    }

    /**
     * Create an authentication context policy for SAML
     *
     * @param array<string> $allowedContexts Allowed authentication context class refs
     * @param int $maxAgeSeconds Maximum age of authentication in seconds
     * @return callable
     */
    public static function authenticationContextPolicy(array $allowedContexts = [], int $maxAgeSeconds = 3600): callable
    {
        return function (string $userId, string $permission, array $context) use ($allowedContexts, $maxAgeSeconds) {
            $claims = $context['token_claims'] ?? null;
            
            if (!$claims) {
                return false;
            }

            // Check authentication context class reference (SAML ACR)
            if (!empty($allowedContexts)) {
                $acr = $claims->acr ?? null;
                if (!$acr || !in_array($acr, $allowedContexts, true)) {
                    return false;
                }
            }

            // Check authentication age
            $authTime = $claims->auth_time ?? $claims->iat ?? null;
            if ($authTime) {
                $age = time() - $authTime;
                if ($age > $maxAgeSeconds) {
                    return false;
                }
            }

            return true;
        };
    }

    /**
     * Create a session policy that validates session state
     *
     * @param int $maxSessionAge Maximum session age in seconds
     * @param bool $requireSessionIndex Whether SAML session index is required
     * @return callable
     */
    public static function sessionPolicy(int $maxSessionAge = 28800, bool $requireSessionIndex = false): callable
    {
        return function (string $userId, string $permission, array $context) use ($maxSessionAge, $requireSessionIndex) {
            $claims = $context['token_claims'] ?? null;
            
            if (!$claims) {
                return false;
            }

            // Check session index for SAML
            if ($requireSessionIndex && ($context['token_type'] ?? '') === 'saml') {
                if (!isset($claims->session_index)) {
                    return false;
                }
            }

            // Check session age
            $sessionStart = $claims->auth_time ?? $claims->iat ?? null;
            if ($sessionStart) {
                $sessionAge = time() - $sessionStart;
                if ($sessionAge > $maxSessionAge) {
                    return false;
                }
            }

            return true;
        };
    }

    /**
     * Add a policy to the enforcer
     *
     * @param callable $policy The policy function
     * @return void
     */
    public function addPolicy(callable $policy): void
    {
        $this->policies[] = $policy;
    }

    /**
     * Add multiple policies to the enforcer
     *
     * @param array<callable> $policies Array of policy functions
     * @return void
     */
    public function addPolicies(array $policies): void
    {
        $this->policies = array_merge($this->policies, $policies);
    }

    /**
     * Add a policy specific to a function/permission
     *
     * @param string $permission The permission this policy applies to
     * @param callable $policy The policy function
     * @return void
     */
    public function addFunctionPolicy(string $permission, callable $policy): void
    {
        if (!isset($this->functionPolicies[$permission])) {
            $this->functionPolicies[$permission] = [];
        }
        $this->functionPolicies[$permission][] = $policy;
    }

    /**
     * Remove all policies
     *
     * @return void
     */
    public function clearPolicies(): void
    {
        $this->policies = [];
    }

    /**
     * Get all registered policies
     *
     * @return array<callable>
     */
    public function getPolicies(): array
    {
        return $this->policies;
    }

    /**
     * Evaluate a single policy
     *
     * @param callable $policy The policy function
     * @param string $userId The user ID
     * @param string $permission The permission being checked
     * @param array<string, mixed> $context Additional context
     * @return bool True if policy passes
     */
    private function evaluatePolicy(callable $policy, string $userId, string $permission, array $context): bool
    {
        try {
            return (bool) call_user_func($policy, $userId, $permission, $context);
        } catch (\Exception) {
            // If policy evaluation fails, deny access
            return false;
        }
    }

    /**
     * Create a time-based policy
     *
     * @param string $startTime Start time (e.g., '09:00')
     * @param string $endTime End time (e.g., '17:00')
     * @param string $timezone Timezone (default: UTC)
     * @return callable
     */
    public static function timeBasedPolicy(string $startTime, string $endTime, string $timezone = 'UTC'): callable
    {
        return function (string $userId, string $permission, array $context) use ($startTime, $endTime, $timezone) {
            $now = new \DateTime('now', new \DateTimeZone($timezone));
            $start = \DateTime::createFromFormat('H:i', $startTime, new \DateTimeZone($timezone));
            $end = \DateTime::createFromFormat('H:i', $endTime, new \DateTimeZone($timezone));

            return $now >= $start && $now <= $end;
        };
    }

    /**
     * Create an IP-based policy
     *
     * @param array<string> $allowedIps Array of allowed IP addresses or CIDR blocks
     * @return callable
     */
    public static function ipBasedPolicy(array $allowedIps): callable
    {
        return function (string $userId, string $permission, array $context) use ($allowedIps) {
            $userIp = $context['ip_address'] ?? null;
            
            if (!$userIp) {
                return false;
            }

            foreach ($allowedIps as $allowedIp) {
                if (self::ipMatches($userIp, $allowedIp)) {
                    return true;
                }
            }

            return false;
        };
    }

    /**
     * Create a resource ownership policy
     *
     * @param string $resourceIdKey The key in context containing the resource ID
     * @param string $ownerIdKey The key in context containing the owner ID
     * @return callable
     */
    public static function resourceOwnershipPolicy(string $resourceIdKey = 'resource_id', string $ownerIdKey = 'owner_id'): callable
    {
        return function (string $userId, string $permission, array $context) use ($resourceIdKey, $ownerIdKey) {
            $ownerId = $context[$ownerIdKey] ?? null;
            
            return $ownerId && $ownerId === $userId;
        };
    }

    /**
     * Create a least privilege policy for sensitive operations
     *
     * @param array<string> $requiredRoles Roles required for access
     * @param array<string> $allowedIps Optional IP restrictions
     * @param bool $requireMfa Whether MFA is required
     * @return callable
     */
    public static function leastPrivilegePolicy(array $requiredRoles = [], array $allowedIps = [], bool $requireMfa = false): callable
    {
        return function (string $userId, string $permission, array $context) use ($requiredRoles, $allowedIps, $requireMfa) {
            // Check role requirements
            if (!empty($requiredRoles)) {
                $userRoles = $context['roles'] ?? [];
                $hasRequiredRole = !empty(array_intersect($requiredRoles, $userRoles));
                if (!$hasRequiredRole) {
                    return false;
                }
            }

            // Check IP restrictions
            if (!empty($allowedIps)) {
                $userIp = $context['ip_address'] ?? null;
                if (!$userIp || !self::isIpAllowed($userIp, $allowedIps)) {
                    return false;
                }
            }

            // Check MFA requirement
            if ($requireMfa) {
                $mfaVerified = $context['mfa_verified'] ?? false;
                if (!$mfaVerified) {
                    return false;
                }
            }

            return true;
        };
    }

    /**
     * Check if an IP address matches a pattern (supports CIDR)
     *
     * @param string $ip The IP address to check
     * @param string $pattern The pattern (IP or CIDR block)
     * @return bool
     */
    private static function ipMatches(string $ip, string $pattern): bool
    {
        if ($ip === $pattern) {
            return true;
        }

        if (str_contains($pattern, '/')) {
            [$subnet, $mask] = explode('/', $pattern);
            $ipLong = ip2long($ip);
            $subnetLong = ip2long($subnet);
            $maskLong = -1 << (32 - (int) $mask);

            return ($ipLong & $maskLong) === ($subnetLong & $maskLong);
        }

        return false;
    }
}