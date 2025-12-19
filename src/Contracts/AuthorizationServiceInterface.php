<?php

declare(strict_types=1);

namespace authlib\Auth\Contracts;

/**
 * Interface for authorization service
 */
interface AuthorizationServiceInterface
{
    /**
     * Check if a user has a specific permission
     *
     * @param string $userId The user ID
     * @param string $permission The permission to check
     * @param array<string, mixed> $context Additional context for permission check
     * @return bool True if user has permission
     */
    public function hasPermission(string $userId, string $permission, array $context = []): bool;

    /**
     * Check if a user has any of the specified permissions
     *
     * @param string $userId The user ID
     * @param array<string> $permissions Array of permissions to check
     * @param array<string, mixed> $context Additional context for permission check
     * @return bool True if user has any of the permissions
     */
    public function hasAnyPermission(string $userId, array $permissions, array $context = []): bool;

    /**
     * Check if a user has all of the specified permissions
     *
     * @param string $userId The user ID
     * @param array<string> $permissions Array of permissions to check
     * @param array<string, mixed> $context Additional context for permission check
     * @return bool True if user has all permissions
     */
    public function hasAllPermissions(string $userId, array $permissions, array $context = []): bool;

    /**
     * Check if a user has a specific role
     *
     * @param string $userId The user ID
     * @param string $role The role to check
     * @return bool True if user has role
     */
    public function hasRole(string $userId, string $role): bool;

    /**
     * Get all permissions for a user (including role-based permissions)
     *
     * @param string $userId The user ID
     * @return array<string> Array of permission strings
     */
    public function getAllPermissions(string $userId): array;

    /**
     * Get all roles for a user
     *
     * @param string $userId The user ID
     * @return array<string> Array of role strings
     */
    public function getAllRoles(string $userId): array;

    /**
     * Authorize a request with token validation and permission checking
     *
     * @param string $token The authentication token
     * @param string $permission The required permission
     * @param array<string, mixed> $context Additional context for permission check
     * @return bool True if authorized
     * @throws \Exception When token validation fails
     */
    public function authorize(string $token, string $permission, array $context = []): bool;

    /**
     * Check if a user has a specific permission based on their group memberships
     *
     * @param string $userId The user identifier
     * @param string[] $groupIds Array of group identifiers the user belongs to
     * @param string $permission The permission to check
     * @return bool True if user has permission
     */
    public function userHasPermission(string $userId, array $groupIds, string $permission): bool;
}