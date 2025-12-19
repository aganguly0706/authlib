<?php

declare(strict_types=1);

namespace authlib\Auth\Auth;

use authlib\Auth\Contracts\ClaimsExtractorInterface;
use InvalidArgumentException;
use stdClass;

/**
 * Default implementation for extracting claims from JWT tokens and SAML assertions
 * Supports both OIDC and SAML token formats
 */
class DefaultClaimsExtractor implements ClaimsExtractorInterface
{
    public function __construct(
        private array $config = []
    ) {
        // Default configuration
        $this->config = array_merge([
            'user_id_claim' => 'sub',
            'roles_claim' => 'roles',
            'permissions_claim' => 'permissions',
            'email_claim' => 'email',
            'name_claim' => 'name',
            'groups_claim' => 'groups',
        ], $config);
    }

    public function extractClaims(stdClass $payload): array
    {
        $claims = [];

        // Extract standard claims
        $claims['user_id'] = $this->extractUserId($payload);
        $claims['roles'] = $this->extractRoles($payload);
        $claims['groups'] = $this->extractGroups($payload);
        $claims['permissions'] = $this->getPermissions($payload);
        
        // Extract common profile claims
        if (isset($payload->{$this->config['email_claim']})) {
            $claims['email'] = $payload->{$this->config['email_claim']};
        }
        
        if (isset($payload->{$this->config['name_claim']})) {
            $claims['name'] = $payload->{$this->config['name_claim']};
        }

        // Extract custom claims
        $claims['custom'] = $this->getCustomClaims($payload);

        return $claims;
    }

    public function getUserId(stdClass $payload): ?string
    {
        return $this->extractUserId($payload);
    }

    public function getRoles(stdClass $payload): array
    {
        return $this->extractRoles($payload);
    }

    public function getPermissions(stdClass $payload): array
    {
        $claim = $this->config['permissions_claim'];
        
        if (!isset($payload->$claim)) {
            return [];
        }

        $permissions = $payload->$claim;
        
        if (is_string($permissions)) {
            return [$permissions];
        }
        
        if (is_array($permissions)) {
            return array_map('strval', $permissions);
        }

        return [];
    }

    public function getCustomClaims(stdClass $payload): array
    {
        $standardClaims = [
            // JWT/OIDC standard claims
            'iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti',
            'given_name', 'family_name', 'email', 'name', 'preferred_username',
            
            // SAML specific claims
            'name_id_format', 'session_index', 'acr', 'auth_time',
            
            // Common claims from config
            $this->config['roles_claim'],
            $this->config['permissions_claim'],
            $this->config['email_claim'],
            $this->config['name_claim'],
            $this->config['groups_claim'],
        ];

        $customClaims = [];
        
        foreach ($payload as $key => $value) {
            if (!in_array($key, $standardClaims, true)) {
                $customClaims[$key] = $value;
            }
        }

        return $customClaims;
    }

    /**
     * Extract groups from both OIDC and SAML claims
     */
    public function extractGroups($claims): array
    {
        // Handle both stdClass and array formats
        if ($claims instanceof stdClass) {
            $claimsArray = (array) $claims;
        } else {
            $claimsArray = (array) $claims;
        }

        // Try multiple possible group claim sources
        $groups = [];
        
        // Standard groups claim
        if (isset($claimsArray['groups'])) {
            $groups = array_merge($groups, (array) $claimsArray['groups']);
        }
        
        // SAML memberOf attribute (common in Active Directory)
        if (isset($claimsArray['memberof'])) {
            $groups = array_merge($groups, (array) $claimsArray['memberof']);
        }
        
        // Microsoft Groups claim
        if (isset($claimsArray['http://schemas.microsoft.com/ws/2008/06/identity/claims/groups'])) {
            $groups = array_merge($groups, (array) $claimsArray['http://schemas.microsoft.com/ws/2008/06/identity/claims/groups']);
        }
        
        // Roles as groups (fallback)
        if (empty($groups) && isset($claimsArray['roles'])) {
            $groups = array_merge($groups, (array) $claimsArray['roles']);
        }

        return array_values(array_unique(array_map('strval', $groups)));
    }

    /**
     * Extract user ID from both OIDC and SAML claims
     */
    public function extractUserId($claims): string
    {
        // Handle both stdClass and array formats
        if ($claims instanceof stdClass) {
            $claimsArray = (array) $claims;
        } else {
            $claimsArray = (array) $claims;
        }

        // Try different user ID claims in order of preference
        $userIdCandidates = [
            'sub',                    // Standard JWT subject
            'user_id',               // Custom user ID
            'preferred_username',    // OIDC preferred username
            'upn',                   // User Principal Name
            'email',                 // Email as fallback
            'name',                  // Name as last resort
        ];

        foreach ($userIdCandidates as $claim) {
            if (isset($claimsArray[$claim]) && !empty($claimsArray[$claim])) {
                return (string) $claimsArray[$claim];
            }
        }

        return 'unknown';
    }

    /**
     * Extract roles from both OIDC and SAML claims
     */
    public function extractRoles($claims): array
    {
        // Handle both stdClass and array formats
        if ($claims instanceof stdClass) {
            $claimsArray = (array) $claims;
        } else {
            $claimsArray = (array) $claims;
        }

        $roles = [];
        
        // Standard roles claim
        if (isset($claimsArray['roles'])) {
            $roles = array_merge($roles, (array) $claimsArray['roles']);
        }
        
        // Microsoft Role claim (SAML)
        if (isset($claimsArray['http://schemas.microsoft.com/ws/2008/06/identity/claims/role'])) {
            $roles = array_merge($roles, (array) $claimsArray['http://schemas.microsoft.com/ws/2008/06/identity/claims/role']);
        }
        
        // Generic role claim
        if (isset($claimsArray['role'])) {
            $roleClaim = $claimsArray['role'];
            if (is_string($roleClaim)) {
                $roles[] = $roleClaim;
            } elseif (is_array($roleClaim)) {
                $roles = array_merge($roles, $roleClaim);
            }
        }

        return array_values(array_unique(array_map('strval', $roles)));
    }

    /**
     * Check if claims appear to be from a SAML assertion
     */
    public function isSamlClaims($claims): bool
    {
        if ($claims instanceof stdClass) {
            return isset($claims->name_id_format) || isset($claims->session_index) || isset($claims->acr);
        }
        
        if (is_array($claims)) {
            return isset($claims['name_id_format']) || isset($claims['session_index']) || isset($claims['acr']);
        }
        
        return false;
    }

    /**
     * Extract authentication context information (mainly for SAML)
     */
    public function extractAuthenticationContext($claims): array
    {
        if ($claims instanceof stdClass) {
            $claimsArray = (array) $claims;
        } else {
            $claimsArray = (array) $claims;
        }

        return [
            'auth_time' => $claimsArray['auth_time'] ?? null,
            'session_index' => $claimsArray['session_index'] ?? null,
            'acr' => $claimsArray['acr'] ?? null, // Authentication Context Class Reference
            'amr' => $claimsArray['amr'] ?? null, // Authentication Methods References
        ];
    }
}