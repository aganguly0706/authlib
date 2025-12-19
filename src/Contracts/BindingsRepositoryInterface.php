<?php

declare(strict_types=1);

namespace authlib\Auth\Contracts;

/**
 * Interface for managing role/permission bindings
 */
interface BindingsRepositoryInterface
{
    /**
     * Get permissions for a user ID
     *
     * @param string $userId The user ID
     * @return array<string> Array of permission strings
     */
    public function getPermissionsForUser(string $userId): array;

    /**
     * Get roles for a user ID
     *
     * @param string $userId The user ID
     * @return array<string> Array of role strings
     */
    public function getRolesForUser(string $userId): array;

    /**
     * Get permissions for a role
     *
     * @param string $role The role name
     * @return array<string> Array of permission strings
     */
    public function getPermissionsForRole(string $role): array;

    /**
     * Bind a permission to a user
     *
     * @param string $userId The user ID
     * @param string $permission The permission string
     * @return bool Success status
     */
    public function bindPermissionToUser(string $userId, string $permission): bool;

    /**
     * Bind a role to a user
     *
     * @param string $userId The user ID
     * @param string $role The role name
     * @return bool Success status
     */
    public function bindRoleToUser(string $userId, string $role): bool;

    /**
     * Bind a permission to a role
     *
     * @param string $role The role name
     * @param string $permission The permission string
     * @return bool Success status
     */
    public function bindPermissionToRole(string $role, string $permission): bool;

    /**
     * Remove a permission from a user
     *
     * @param string $userId The user ID
     * @param string $permission The permission string
     * @return bool Success status
     */
    public function unbindPermissionFromUser(string $userId, string $permission): bool;

    /**
     * Remove a role from a user
     *
     * @param string $userId The user ID
     * @param string $role The role name
     * @return bool Success status
     */
    public function unbindRoleFromUser(string $userId, string $role): bool;

    /**
     * Clear all cached bindings
     *
     * @return bool Success status
     */
    public function clearCache(): bool;

    /**
     * Get role IDs for given group IDs
     *
     * @param string[] $groupIds Array of group identifiers
     * @return int[] Array of role IDs
     */
    public function getRolesForGroups(array $groupIds): array;

    /**
     * Get permission names for given role IDs
     *
     * @param int[] $roleIds Array of role IDs
     * @return string[] Array of permission names
     */
    public function getPermissionsForRoles(array $roleIds): array;

    /**
     * Get function keys for a given permission
     *
     * @param string $permission Permission name
     * @return string[] Array of function keys
     */
    public function getFunctionsForPermission(string $permission): array;
}