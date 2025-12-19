<?php

declare(strict_types=1);

namespace authlib\Auth\Utils;

/**
 * Utility for mapping external IDs to internal user IDs
 */
class IdMapping
{
    /**
     * Extract user ID from various token claim formats
     *
     * @param array $claims Token claims
     * @param array $config Mapping configuration
     * @return string|null The mapped user ID
     */
    public static function extractUserId(array $claims, array $config = []): ?string
    {
        $config = array_merge([
            'primary_claim' => 'sub',
            'fallback_claims' => ['user_id', 'uid', 'id'],
            'email_as_fallback' => true,
            'transformations' => [],
        ], $config);

        // Try primary claim first
        $userId = $claims[$config['primary_claim']] ?? null;
        
        if ($userId) {
            return self::applyTransformations($userId, $config['transformations']);
        }

        // Try fallback claims
        foreach ($config['fallback_claims'] as $claim) {
            $userId = $claims[$claim] ?? null;
            if ($userId) {
                return self::applyTransformations($userId, $config['transformations']);
            }
        }

        // Use email as fallback if enabled
        if ($config['email_as_fallback'] && isset($claims['email'])) {
            return self::applyTransformations($claims['email'], $config['transformations']);
        }

        return null;
    }

    /**
     * Map external role names to internal role names
     *
     * @param array $externalRoles External role names
     * @param array $roleMapping Role mapping configuration
     * @return array Mapped internal role names
     */
    public static function mapRoles(array $externalRoles, array $roleMapping = []): array
    {
        $mappedRoles = [];

        foreach ($externalRoles as $externalRole) {
            if (isset($roleMapping[$externalRole])) {
                $mapped = $roleMapping[$externalRole];
                if (is_array($mapped)) {
                    $mappedRoles = array_merge($mappedRoles, $mapped);
                } else {
                    $mappedRoles[] = $mapped;
                }
            } else {
                // If no mapping defined, use the role as-is
                $mappedRoles[] = $externalRole;
            }
        }

        return array_unique($mappedRoles);
    }

    /**
     * Map external permissions to internal permissions
     *
     * @param array $externalPermissions External permission names
     * @param array $permissionMapping Permission mapping configuration
     * @return array Mapped internal permission names
     */
    public static function mapPermissions(array $externalPermissions, array $permissionMapping = []): array
    {
        $mappedPermissions = [];

        foreach ($externalPermissions as $externalPermission) {
            if (isset($permissionMapping[$externalPermission])) {
                $mapped = $permissionMapping[$externalPermission];
                if (is_array($mapped)) {
                    $mappedPermissions = array_merge($mappedPermissions, $mapped);
                } else {
                    $mappedPermissions[] = $mapped;
                }
            } else {
                // If no mapping defined, use the permission as-is
                $mappedPermissions[] = $externalPermission;
            }
        }

        return array_unique($mappedPermissions);
    }

    /**
     * Create a normalized user ID from various sources
     *
     * @param string $userId The user ID to normalize
     * @param string $issuer The token issuer
     * @param string $format The format to use ('issuer_prefixed', 'hashed', 'plain')
     * @return string Normalized user ID
     */
    public static function normalizeUserId(string $userId, string $issuer = '', string $format = 'issuer_prefixed'): string
    {
        return match($format) {
            'issuer_prefixed' => $issuer ? self::createIssuerPrefixedId($userId, $issuer) : $userId,
            'hashed' => hash('sha256', $userId . $issuer),
            'plain' => $userId,
            default => $userId,
        };
    }

    /**
     * Extract tenant/organization ID from token claims
     *
     * @param array $claims Token claims
     * @param array $config Tenant mapping configuration
     * @return string|null The tenant ID
     */
    public static function extractTenantId(array $claims, array $config = []): ?string
    {
        $config = array_merge([
            'tenant_claims' => ['tenant_id', 'org_id', 'organization', 'tenant'],
            'domain_extraction' => false,
            'domain_claim' => 'email',
        ], $config);

        // Try direct tenant claims
        foreach ($config['tenant_claims'] as $claim) {
            $tenantId = $claims[$claim] ?? null;
            if ($tenantId) {
                return (string) $tenantId;
            }
        }

        // Extract from domain if enabled
        if ($config['domain_extraction'] && isset($claims[$config['domain_claim']])) {
            $email = $claims[$config['domain_claim']];
            if (is_string($email) && str_contains($email, '@')) {
                return substr($email, strpos($email, '@') + 1);
            }
        }

        return null;
    }

    /**
     * Apply transformations to a user ID
     *
     * @param string $userId The user ID
     * @param array $transformations Array of transformation functions
     * @return string Transformed user ID
     */
    private static function applyTransformations(string $userId, array $transformations): string
    {
        foreach ($transformations as $transformation) {
            if (is_callable($transformation)) {
                $userId = call_user_func($transformation, $userId);
            } elseif (is_string($transformation)) {
                $userId = match($transformation) {
                    'lowercase' => strtolower($userId),
                    'uppercase' => strtoupper($userId),
                    'trim' => trim($userId),
                    'email_local_part' => str_contains($userId, '@') ? substr($userId, 0, strpos($userId, '@')) : $userId,
                    default => $userId,
                };
            }
        }

        return $userId;
    }

    /**
     * Create an issuer-prefixed user ID
     *
     * @param string $userId The user ID
     * @param string $issuer The issuer
     * @return string Prefixed user ID
     */
    private static function createIssuerPrefixedId(string $userId, string $issuer): string
    {
        // Create a short prefix from the issuer
        $prefix = self::createIssuerPrefix($issuer);
        
        return $prefix . ':' . $userId;
    }

    /**
     * Create a short prefix from an issuer URL
     *
     * @param string $issuer The issuer URL
     * @return string Short prefix
     */
    private static function createIssuerPrefix(string $issuer): string
    {
        // Parse URL and create prefix from domain
        $parsed = parse_url($issuer);
        $domain = $parsed['host'] ?? $issuer;
        
        // Remove common prefixes and create short form
        $domain = preg_replace('/^(auth\.|accounts\.|login\.)/', '', $domain);
        $domain = preg_replace('/\.(com|org|net|io)$/', '', $domain);
        
        // Take first part if multiple segments
        $parts = explode('.', $domain);
        
        return strtolower($parts[0]);
    }
}