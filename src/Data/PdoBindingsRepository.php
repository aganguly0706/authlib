<?php

declare(strict_types=1);

namespace authlib\Auth\Data;

use PDO;
use authlib\Auth\Contracts\BindingsRepositoryInterface;

/**
 * PDO-based repository for managing role/permission bindings
 * Optimized with prepared statements and simple in-memory caching
 */
final class PdoBindingsRepository implements BindingsRepositoryInterface
{
    /** @var array<string, mixed> Simple in-memory cache */
    private array $cache = [];
    
    public function __construct(private readonly PDO $pdo) {}

    /**
     * Get role IDs for given group IDs
     *
     * @param string[] $groupIds Array of group identifiers
     * @return int[] Array of role IDs
     */
    public function getRolesForGroups(array $groupIds): array
    {
        if (empty($groupIds)) {
            return [];
        }

        // Sanitize all group IDs
        $groupIds = array_map([$this, 'sanitizeGroupId'], $groupIds);
        $groupIds = array_filter($groupIds); // Remove empty after sanitization
        
        if (empty($groupIds)) {
            return [];
        }

        $cacheKey = 'roles_for_groups_' . hash('sha256', implode(',', $groupIds));
        if (isset($this->cache[$cacheKey])) {
            return $this->cache[$cacheKey];
        }

        $placeholders = implode(',', array_fill(0, count($groupIds), '?'));
        $sql = "SELECT DISTINCT role FROM group_roles WHERE group_id IN ($placeholders)";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute(array_values($groupIds));
        
        $roles = $stmt->fetchAll(PDO::FETCH_COLUMN);
        
        // Sanitize role names
        $roles = array_map([$this, 'sanitizeRole'], $roles);
        
        $this->cache[$cacheKey] = $roles;
        return $roles;
    }

    /**
     * Get permission names for given role IDs
     *
     * @param int[] $roleIds Array of role IDs
     * @return string[] Array of permission names
     */
    public function getPermissionsForRoles(array $roleIds): array
    {
        if (!$roleIds) return [];
        
        $cacheKey = 'permissions_for_roles_' . md5(implode(',', $roleIds));
        if (isset($this->cache[$cacheKey])) {
            return $this->cache[$cacheKey];
        }
        
        $placeholders = implode(',', array_fill(0, count($roleIds), '?'));
        $sql = "SELECT DISTINCT p.PermissionName
                FROM RolePermissions rp
                JOIN Permissions p ON p.PermissionId = rp.PermissionId
                WHERE rp.RoleId IN ($placeholders)";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute(array_values($roleIds));
        
        $permissions = array_map(fn($r) => (string) $r['PermissionName'], $stmt->fetchAll());
        $this->cache[$cacheKey] = $permissions;
        
        return $permissions;
    }

    /**
     * Get function keys for a given permission
     *
     * @param string $permission Permission name
     * @return string[] Array of function keys
     */
    public function getFunctionsForPermission(string $permission): array
    {
        $cacheKey = 'functions_for_permission_' . md5($permission);
        if (isset($this->cache[$cacheKey])) {
            return $this->cache[$cacheKey];
        }
        
        $sql = "SELECT f.FunctionKey
                FROM PermissionFunctionBindings pfb
                JOIN Permissions p ON p.PermissionId = pfb.PermissionId
                JOIN Functions f ON f.FunctionId = pfb.FunctionId
                WHERE p.PermissionName = ?";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([$permission]);
        
        $functions = array_map(fn($r) => (string) $r['FunctionKey'], $stmt->fetchAll());
        $this->cache[$cacheKey] = $functions;
        
        return $functions;
    }

    /**
     * Get permissions for a specific user with input sanitization
     *
     * @param string $userId User identifier (will be sanitized)
     * @return string[] Array of permission names
     */
    public function getPermissionsForUser(string $userId): array
    {
        $userId = $this->sanitizeUserId($userId);
        $cacheKey = 'permissions_for_user_' . hash('sha256', $userId);
        
        if (isset($this->cache[$cacheKey])) {
            return $this->cache[$cacheKey];
        }

        // Direct user permissions - using prepared statements
        $stmt = $this->pdo->prepare('
            SELECT permission FROM user_permissions 
            WHERE user_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL 1 YEAR)
        ');
        $stmt->execute([$userId]);
        $directPermissions = $stmt->fetchAll(PDO::FETCH_COLUMN);

        // Role-based permissions - using prepared statements
        $stmt = $this->pdo->prepare('
            SELECT DISTINCT rp.permission 
            FROM user_roles ur 
            JOIN role_permissions rp ON ur.role = rp.role 
            WHERE ur.user_id = ? AND ur.created_at >= DATE_SUB(NOW(), INTERVAL 1 YEAR)
        ');
        $stmt->execute([$userId]);
        $rolePermissions = $stmt->fetchAll(PDO::FETCH_COLUMN);

        $permissions = array_unique(array_merge($directPermissions, $rolePermissions));
        
        // Sanitize permission names before caching
        $permissions = array_map([$this, 'sanitizePermission'], $permissions);
        
        $this->cache[$cacheKey] = $permissions;
        return $permissions;
    }

    /**
     * Get roles for a specific user
     *
     * @param string $userId User identifier
     * @return string[] Array of role names
     */
    public function getRolesForUser(string $userId): array
    {
        $cacheKey = 'roles_for_user_' . md5($userId);
        if (isset($this->cache[$cacheKey])) {
            return $this->cache[$cacheKey];
        }

        $stmt = $this->pdo->prepare('SELECT role FROM user_roles WHERE user_id = ?');
        $stmt->execute([$userId]);
        $roles = $stmt->fetchAll(PDO::FETCH_COLUMN);

        $this->cache[$cacheKey] = $roles;
        return $roles;
    }

    /**
     * Get permissions for a specific role
     *
     * @param string $role Role name
     * @return string[] Array of permission names
     */
    public function getPermissionsForRole(string $role): array
    {
        $cacheKey = 'permissions_for_role_' . md5($role);
        if (isset($this->cache[$cacheKey])) {
            return $this->cache[$cacheKey];
        }

        $stmt = $this->pdo->prepare('SELECT permission FROM role_permissions WHERE role = ?');
        $stmt->execute([$role]);
        $permissions = $stmt->fetchAll(PDO::FETCH_COLUMN);

        $this->cache[$cacheKey] = $permissions;
        return $permissions;
    }

    /**
     * Bind a permission to a user with validation
     *
     * @param string $userId User identifier (will be sanitized)
     * @param string $permission Permission name (will be sanitized)
     * @return bool Success status
     */
    public function bindPermissionToUser(string $userId, string $permission): bool
    {
        $userId = $this->sanitizeUserId($userId);
        $permission = $this->sanitizePermission($permission);
        
        if (empty($userId) || empty($permission)) {
            return false;
        }

        // Use INSERT IGNORE to prevent duplicates
        $stmt = $this->pdo->prepare('
            INSERT IGNORE INTO user_permissions (user_id, permission, created_at) 
            VALUES (?, ?, NOW())
        ');
        $result = $stmt->execute([$userId, $permission]);
        
        // Invalidate relevant cache entries
        $this->invalidateUserCache($userId);
        
        return $result;
    }

    /**
     * Bind a role to a user
     *
     * @param string $userId User identifier
     * @param string $role Role name
     * @return bool Success status
     */
    public function bindRoleToUser(string $userId, string $role): bool
    {
        $stmt = $this->pdo->prepare('
            INSERT IGNORE INTO user_roles (user_id, role, created_at) 
            VALUES (?, ?, NOW())
        ');
        $result = $stmt->execute([$userId, $role]);
        
        // Invalidate relevant cache entries
        $this->invalidateUserCache($userId);
        
        return $result;
    }

    /**
     * Bind a permission to a role
     *
     * @param string $role Role name
     * @param string $permission Permission name
     * @return bool Success status
     */
    public function bindPermissionToRole(string $role, string $permission): bool
    {
        $stmt = $this->pdo->prepare('
            INSERT IGNORE INTO role_permissions (role, permission, created_at) 
            VALUES (?, ?, NOW())
        ');
        $result = $stmt->execute([$role, $permission]);
        
        // Invalidate relevant cache entries
        $this->invalidateRoleCache($role);
        
        return $result;
    }

    /**
     * Unbind a permission from a user
     *
     * @param string $userId User identifier
     * @param string $permission Permission name
     * @return bool Success status
     */
    public function unbindPermissionFromUser(string $userId, string $permission): bool
    {
        $stmt = $this->pdo->prepare('
            DELETE FROM user_permissions WHERE user_id = ? AND permission = ?
        ');
        $result = $stmt->execute([$userId, $permission]);
        
        // Invalidate relevant cache entries
        $this->invalidateUserCache($userId);
        
        return $result;
    }

    /**
     * Unbind a role from a user
     *
     * @param string $userId User identifier
     * @param string $role Role name
     * @return bool Success status
     */
    public function unbindRoleFromUser(string $userId, string $role): bool
    {
        $stmt = $this->pdo->prepare('
            DELETE FROM user_roles WHERE user_id = ? AND role = ?
        ');
        $result = $stmt->execute([$userId, $role]);
        
        // Invalidate relevant cache entries
        $this->invalidateUserCache($userId);
        
        return $result;
    }

    /**
     * Clear all cache entries
     *
     * @return bool Always returns true
     */
    public function clearCache(): bool
    {
        $this->cache = [];
        return true;
    }

    /**
     * Generate cache key for consistent caching
     *
     * @param string $prefix Cache key prefix
     * @param string $identifier Unique identifier
     * @return string Generated cache key
     */
    public function getCacheKey(string $prefix, string $identifier): string
    {
        return $prefix . '_' . md5($identifier);
    }

    /**
     * Invalidate cache entries related to a specific user
     *
     * @param string $userId User identifier
     */
    private function invalidateUserCache(string $userId): void
    {
        $userHash = md5($userId);
        $keysToRemove = [];
        
        foreach (array_keys($this->cache) as $key) {
            if (strpos($key, 'permissions_for_user_' . $userHash) !== false ||
                strpos($key, 'roles_for_user_' . $userHash) !== false) {
                $keysToRemove[] = $key;
            }
        }
        
        foreach ($keysToRemove as $key) {
            unset($this->cache[$key]);
        }
    }

    /**
     * Invalidate cache entries related to a specific role
     *
     * @param string $role Role name
     */
    private function invalidateRoleCache(string $role): void
    {
        $roleHash = md5($role);
        $keysToRemove = [];
        
        foreach (array_keys($this->cache) as $key) {
            if (strpos($key, 'permissions_for_role_' . $roleHash) !== false) {
                $keysToRemove[] = $key;
            }
        }
        
        foreach ($keysToRemove as $key) {
            unset($this->cache[$key]);
        }
    }

    /**
     * Get cache statistics
     *
     * @return array<string, int> Cache statistics
     */
    public function getCacheStats(): array
    {
        return [
            'total_entries' => count($this->cache),
            'memory_usage' => memory_get_usage()
        ];
    }

    /**
     * Get the underlying PDO instance
     *
     * @return PDO PDO instance
     */
    protected function getPdo(): PDO
    {
        return $this->pdo;
    }

    /**
     * Sanitize user ID to prevent SQL injection and normalize format
     */
    private function sanitizeUserId(string $userId): string
    {
        // Remove control characters and limit length
        $sanitized = preg_replace('/[\x00-\x1F\x7F]/', '', trim($userId));
        
        // Only allow alphanumeric, email characters, and common separators
        $sanitized = preg_replace('/[^A-Za-z0-9@._-]/', '', $sanitized);
        
        // Limit length to prevent buffer overflows
        return substr($sanitized, 0, 255);
    }

    /**
     * Sanitize permission string to ensure valid format
     */
    private function sanitizePermission(string $permission): string
    {
        // Remove control characters and trim
        $sanitized = preg_replace('/[\x00-\x1F\x7F]/', '', trim($permission));
        
        // Only allow alphanumeric, dots, underscores, and hyphens
        $sanitized = preg_replace('/[^A-Za-z0-9._-]/', '', $sanitized);
        
        // Limit length
        return substr($sanitized, 0, 100);
    }

    /**
     * Sanitize role string to ensure valid format
     */
    private function sanitizeRole(string $role): string
    {
        // Remove control characters and trim
        $sanitized = preg_replace('/[\x00-\x1F\x7F]/', '', trim($role));
        
        // Only allow alphanumeric, underscores, and hyphens
        $sanitized = preg_replace('/[^A-Za-z0-9_-]/', '', $sanitized);
        
        // Limit length
        return substr($sanitized, 0, 50);
    }

    /**
     * Sanitize group ID (often AD DNs) to prevent injection
     */
    private function sanitizeGroupId(string $groupId): string
    {
        // Remove control characters and trim
        $sanitized = preg_replace('/[\x00-\x1F\x7F]/', '', trim($groupId));
        
        // For AD DNs, allow more characters but still prevent injection
        $sanitized = preg_replace('/[^\x20-\x7E]/', '', $sanitized); // Allow printable ASCII
        
        // Remove potentially dangerous SQL characters
        $sanitized = str_replace(['--', '/*', '*/', ';', '\x00'], '', $sanitized);
        
        // Limit length to prevent buffer overflows
        return substr($sanitized, 0, 500);
    }

    /**
     * Generate bindings hash for policy versioning
     */
    public function generateBindingsHash(): string
    {
        // Query for recent binding changes to create version hash
        $stmt = $this->pdo->prepare('
            SELECT MAX(GREATEST(
                COALESCE(MAX(ur.created_at), "1970-01-01"),
                COALESCE(MAX(up.created_at), "1970-01-01"),
                COALESCE(MAX(rp.created_at), "1970-01-01"),
                COALESCE(MAX(gr.created_at), "1970-01-01")
            )) as last_change
            FROM user_roles ur, user_permissions up, role_permissions rp, group_roles gr
        ');
        $stmt->execute();
        $lastChange = $stmt->fetchColumn();
        
        // Create hash based on last change time and table counts
        $stmt = $this->pdo->prepare('
            SELECT 
                (SELECT COUNT(*) FROM user_roles) as ur_count,
                (SELECT COUNT(*) FROM user_permissions) as up_count,
                (SELECT COUNT(*) FROM role_permissions) as rp_count,
                (SELECT COUNT(*) FROM group_roles) as gr_count
        ');
        $stmt->execute();
        $counts = $stmt->fetch(PDO::FETCH_ASSOC);
        
        $hashData = $lastChange . '_' . implode('_', $counts);
        return hash('sha256', $hashData);
    }
}