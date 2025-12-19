<?php

declare(strict_types=1);

namespace authlib\Auth\Core;

use authlib\Auth\Contracts\AuthorizationServiceInterface;
use authlib\Auth\Contracts\TokenValidatorInterface;
use authlib\Auth\Contracts\ClaimsExtractorInterface;
use authlib\Auth\Contracts\BindingsRepositoryInterface;
use authlib\Auth\Contracts\AuditSinkInterface;

/**
 * Main authorization service with caching and audit support
 */
final class AuthorizationService implements AuthorizationServiceInterface
{
    public function __construct(
        private readonly BindingsRepositoryInterface $repo,
        private readonly AuditSinkInterface $audit,
        private readonly PermissionCache $cache,
        private TokenValidatorInterface $tokenValidator,
        private ClaimsExtractorInterface $claimsExtractor,
        private PolicyEnforcer $policyEnforcer,
        private ?AuditSinkInterface $auditSink = null
    ) {
    }

    public function userHasPermission(string $userId, array $groupIds, string $permission): bool
    {
        $cacheKey = "perm:$userId:$permission:" . md5(implode(',', $groupIds));
        
        if ($this->cache->has($cacheKey)) {
            $decision = $this->cache->get($cacheKey);
            $this->audit->logDecision($userId, $permission, (bool)$decision, ['cache' => true]);
            return (bool)$decision;
        }

        $roleIds = $this->repo->getRolesForGroups($groupIds);
        $perms = $this->repo->getPermissionsForRoles($roleIds);
        $decision = in_array($permission, $perms, true);

        $this->cache->set($cacheKey, $decision, 600); // 10m TTL (align with token TTL)
        $this->audit->logDecision($userId, $permission, $decision, [
            'roles' => $roleIds,
            'groups' => $groupIds,
        ]);

        return $decision;
    }

    public function hasPermission(string $userId, string $permission, array $context = []): bool
    {
        $userPermissions = $this->repo->getPermissionsForUser($userId);
        $hasPermission = in_array($permission, $userPermissions, true);

        // Apply policy enforcement
        if ($hasPermission) {
            $hasPermission = $this->policyEnforcer->enforce($userId, $permission, $context);
        }

        // Audit the check
        if ($this->auditSink) {
            if ($hasPermission) {
                $this->auditSink->logPermissionGranted($userId, $permission, $context);
            } else {
                $this->auditSink->logPermissionDenied($userId, $permission, $context);
            }
        }

        return $hasPermission;
    }

    public function hasAnyPermission(string $userId, array $permissions, array $context = []): bool
    {
        foreach ($permissions as $permission) {
            if ($this->hasPermission($userId, $permission, $context)) {
                return true;
            }
        }

        return false;
    }

    public function hasAllPermissions(string $userId, array $permissions, array $context = []): bool
    {
        foreach ($permissions as $permission) {
            if (!$this->hasPermission($userId, $permission, $context)) {
                return false;
            }
        }

        return true;
    }

    public function hasRole(string $userId, string $role): bool
    {
        $userRoles = $this->repo->getRolesForUser($userId);
        
        if ($this->auditSink) {
            $this->auditSink->logAuthorizationEvent('role_check', $userId, [
                'role' => $role,
                'has_role' => in_array($role, $userRoles, true),
            ]);
        }

        return in_array($role, $userRoles, true);
    }

    public function getAllPermissions(string $userId): array
    {
        return $this->repo->getPermissionsForUser($userId);
    }

    public function getAllRoles(string $userId): array
    {
        return $this->repo->getRolesForUser($userId);
    }

    public function authorize(string $token, string $permission, array $context = []): bool
    {
        try {
            // Validate token
            $payload = $this->tokenValidator->validate($token);
            
            if ($this->auditSink) {
                $this->auditSink->logTokenEvent('token_valid', $this->maskToken($token), [
                    'issuer' => $payload->iss ?? null,
                    'subject' => $payload->sub ?? null,
                ]);
            }

            // Extract claims
            $claims = $this->claimsExtractor->extractClaims($payload);
            $userId = $claims['user_id'] ?? null;

            if (!$userId) {
                if ($this->auditSink) {
                    $this->auditSink->logSecurityEvent('missing_user_id', [
                        'token_claims' => array_keys((array) $payload),
                    ]);
                }
                return false;
            }

            // Check permission
            $hasPermission = $this->hasPermission($userId, $permission, array_merge($context, [
                'token_claims' => $claims,
            ]));

            if ($this->auditSink) {
                $this->auditSink->logAuthorizationEvent('authorization', $userId, [
                    'permission' => $permission,
                    'result' => $hasPermission ? 'granted' : 'denied',
                    'context' => $context,
                ]);
            }

            return $hasPermission;

        } catch (\Exception $e) {
            if ($this->auditSink) {
                $this->auditSink->logTokenEvent('token_invalid', $this->maskToken($token), [
                    'error' => $e->getMessage(),
                ]);
            }
            
            throw $e;
        }
    }

    private function maskToken(string $token): string
    {
        // Only show first and last 8 characters for audit purposes
        if (strlen($token) <= 16) {
            return str_repeat('*', strlen($token));
        }
        
        return substr($token, 0, 8) . str_repeat('*', strlen($token) - 16) . substr($token, -8);
    }
}