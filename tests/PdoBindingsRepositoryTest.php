<?php

declare(strict_types=1);

namespace authlib\Auth\Tests;

use PHPUnit\Framework\TestCase;
use authlib\Auth\Data\PdoBindingsRepository;
use authlib\Auth\Config\DbConfig;
use PDO;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Cache\CacheItemInterface;

/**
 * Enhanced test suite for PdoBindingsRepository with comprehensive database testing
 */
class PdoBindingsRepositoryTest extends TestCase
{
    private PdoBindingsRepository $repository;
    private PDO $pdo;
    private CacheItemPoolInterface $cache;
    private DbConfig $config;

    protected function setUp(): void
    {
        // Create an in-memory SQLite database for testing
        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Create test tables
        $this->createTestTables();

        // Mock cache
        $this->cache = $this->createMock(CacheItemPoolInterface::class);

        // Mock config
        $this->config = $this->createMock(DbConfig::class);
        $this->config->method('getDsn')->willReturn('sqlite::memory:');
        $this->config->method('getUsername')->willReturn('');
        $this->config->method('getPassword')->willReturn('');
        $this->config->method('getOptions')->willReturn([]);
        $this->config->method('getCharset')->willReturn('utf8');

        // Create repository with our test PDO
        $this->repository = new class($this->config, $this->cache) extends PdoBindingsRepository {
            private PDO $testPdo;

            public function __construct(DbConfig $config, ?CacheItemPoolInterface $cache = null)
            {
                parent::__construct($config, $cache);
            }

            public function setTestPdo(PDO $pdo): void
            {
                $this->testPdo = $pdo;
            }

            protected function getPdo(): PDO
            {
                return $this->testPdo ?? parent::getPdo();
            }
        };

        $this->repository->setTestPdo($this->pdo);
    }

    private function createTestTables(): void
    {
        // Create comprehensive schema for testing
        $this->pdo->exec("
            CREATE TABLE user_roles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, role)
            )
        ");

        $this->pdo->exec("
            CREATE TABLE user_permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                permission TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, permission)
            )
        ");

        $this->pdo->exec("
            CREATE TABLE role_permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                role TEXT NOT NULL,
                permission TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(role, permission)
            )
        ");

        $this->pdo->exec("
            CREATE TABLE group_roles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(group_id, role)
            )
        ");

        $this->pdo->exec("
            CREATE TABLE user_groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                group_id TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, group_id)
            )
        ");
    }

    /**
     * Seed test data with various permission scenarios
     */
    private function seedTestData(): void
    {
        // Insert test user roles
        $this->pdo->exec("
            INSERT OR IGNORE INTO user_roles (user_id, role) VALUES 
            ('admin@example.com', 'super_admin'),
            ('admin@example.com', 'manager'),
            ('editor@example.com', 'editor'),
            ('editor@example.com', 'content_creator'),
            ('viewer@example.com', 'viewer'),
            ('nogroup@example.com', 'basic_user')
        ");

        // Insert test user permissions (direct permissions)
        $this->pdo->exec("
            INSERT OR IGNORE INTO user_permissions (user_id, permission) VALUES 
            ('admin@example.com', 'system.maintenance'),
            ('admin@example.com', 'audit.view'),
            ('editor@example.com', 'content.special_edit'),
            ('special@example.com', 'orders.custom_action')
        ");

        // Insert comprehensive role permissions
        $this->pdo->exec("
            INSERT OR IGNORE INTO role_permissions (role, permission) VALUES 
            ('super_admin', 'users.create'),
            ('super_admin', 'users.delete'),
            ('super_admin', 'users.edit'),
            ('super_admin', 'orders.create'),
            ('super_admin', 'orders.edit'),
            ('super_admin', 'orders.delete'),
            ('super_admin', 'orders.view'),
            ('manager', 'orders.create'),
            ('manager', 'orders.edit'),
            ('manager', 'orders.view'),
            ('manager', 'reports.view'),
            ('editor', 'content.create'),
            ('editor', 'content.edit'),
            ('editor', 'orders.view'),
            ('content_creator', 'content.create'),
            ('viewer', 'orders.view'),
            ('viewer', 'content.view'),
            ('basic_user', 'profile.view'),
            ('basic_user', 'profile.edit')
        ");

        // Insert group roles
        $this->pdo->exec("
            INSERT OR IGNORE INTO group_roles (group_id, role) VALUES 
            ('admin_group', 'super_admin'),
            ('admin_group', 'manager'),
            ('editor_group', 'editor'),
            ('editor_group', 'content_creator'),
            ('viewer_group', 'viewer'),
            ('sales_group', 'manager'),
            ('sales_group', 'viewer'),
            ('unknown_group', 'basic_user')
        ");

        // Insert user groups
        $this->pdo->exec("
            INSERT OR IGNORE INTO user_groups (user_id, group_id) VALUES 
            ('admin@example.com', 'admin_group'),
            ('editor@example.com', 'editor_group'),
            ('viewer@example.com', 'viewer_group'),
            ('sales@example.com', 'sales_group'),
            ('unknown@example.com', 'unknown_group')
        ");
    }

    /**
     * Data provider for user permission scenarios
     * @return array<string, array{userId: string, expectedPermissions: array, description: string}>
     */
    public static function userPermissionProvider(): array
    {
        return [
            'admin_user_with_all_permissions' => [
                'userId' => 'admin@example.com',
                'expectedPermissions' => [
                    'system.maintenance', 'audit.view', // Direct permissions
                    'users.create', 'users.delete', 'users.edit', 'orders.create', 'orders.edit', 'orders.delete', 'orders.view', // From super_admin role
                    'reports.view' // From manager role
                ],
                'description' => 'Admin user should have all permissions from roles and direct assignments'
            ],
            'editor_user_with_content_permissions' => [
                'userId' => 'editor@example.com',
                'expectedPermissions' => [
                    'content.special_edit', // Direct permission
                    'content.create', 'content.edit', 'orders.view' // From editor role
                ],
                'description' => 'Editor user should have content-related permissions'
            ],
            'viewer_user_with_limited_permissions' => [
                'userId' => 'viewer@example.com',
                'expectedPermissions' => [
                    'orders.view', 'content.view' // From viewer role
                ],
                'description' => 'Viewer user should have only view permissions'
            ],
            'user_with_no_roles_or_permissions' => [
                'userId' => 'noroles@example.com',
                'expectedPermissions' => [],
                'description' => 'User with no roles or permissions should have empty permission set'
            ],
            'user_with_special_direct_permission' => [
                'userId' => 'special@example.com',
                'expectedPermissions' => [
                    'orders.custom_action' // Only direct permission
                ],
                'description' => 'User with only direct permission should have that specific permission'
            ]
        ];
    }

    /**
     * @dataProvider userPermissionProvider
     */
    public function testGetPermissionsForUserWithVariousScenarios(
        string $userId,
        array $expectedPermissions,
        string $description
    ): void {
        $this->seedTestData();

        // Mock cache miss to force database query
        $cacheItem = $this->createMock(CacheItemInterface::class);
        $cacheItem->method('isHit')->willReturn(false);
        $this->cache->method('getItem')->willReturn($cacheItem);

        $permissions = $this->repository->getPermissionsForUser($userId);

        // Sort both arrays for comparison
        sort($expectedPermissions);
        sort($permissions);

        $this->assertEquals($expectedPermissions, $permissions, $description);
    }

    /**
     * Data provider for group-based role scenarios
     * @return array<string, array{groupIds: array, expectedRoles: array, description: string}>
     */
    public static function groupRoleProvider(): array
    {
        return [
            'admin_group_roles' => [
                'groupIds' => ['admin_group'],
                'expectedRoles' => ['super_admin', 'manager'],
                'description' => 'Admin group should have super_admin and manager roles'
            ],
            'editor_group_roles' => [
                'groupIds' => ['editor_group'],
                'expectedRoles' => ['editor', 'content_creator'],
                'description' => 'Editor group should have editor and content_creator roles'
            ],
            'viewer_group_roles' => [
                'groupIds' => ['viewer_group'],
                'expectedRoles' => ['viewer'],
                'description' => 'Viewer group should have viewer role'
            ],
            'multiple_groups' => [
                'groupIds' => ['editor_group', 'sales_group'],
                'expectedRoles' => ['editor', 'content_creator', 'manager', 'viewer'],
                'description' => 'Multiple groups should combine roles from all groups'
            ],
            'unknown_groups' => [
                'groupIds' => ['nonexistent_group', 'another_unknown_group'],
                'expectedRoles' => [],
                'description' => 'Unknown groups should return empty roles'
            ],
            'no_groups' => [
                'groupIds' => [],
                'expectedRoles' => [],
                'description' => 'Empty groups should return empty roles'
            ]
        ];
    }

    /**
     * @dataProvider groupRoleProvider
     */
    public function testGetRolesForGroupsWithVariousScenarios(
        array $groupIds,
        array $expectedRoles,
        string $description
    ): void {
        $this->seedTestData();

        $roles = $this->repository->getRolesForGroups($groupIds);

        sort($expectedRoles);
        sort($roles);

        $this->assertEquals($expectedRoles, $roles, $description);
    }

    /**
     * Data provider for role permission scenarios
     * @return array<string, array{roles: array, expectedPermissions: array, description: string}>
     */
    public static function rolePermissionProvider(): array
    {
        return [
            'super_admin_permissions' => [
                'roles' => ['super_admin'],
                'expectedPermissions' => [
                    'users.create', 'users.delete', 'users.edit',
                    'orders.create', 'orders.edit', 'orders.delete', 'orders.view'
                ],
                'description' => 'Super admin should have all user and order permissions'
            ],
            'manager_permissions' => [
                'roles' => ['manager'],
                'expectedPermissions' => ['orders.create', 'orders.edit', 'orders.view', 'reports.view'],
                'description' => 'Manager should have order management and reporting permissions'
            ],
            'editor_permissions' => [
                'roles' => ['editor'],
                'expectedPermissions' => ['content.create', 'content.edit', 'orders.view'],
                'description' => 'Editor should have content permissions and order viewing'
            ],
            'multiple_roles' => [
                'roles' => ['editor', 'viewer'],
                'expectedPermissions' => [
                    'content.create', 'content.edit', 'orders.view', 'content.view'
                ],
                'description' => 'Multiple roles should combine permissions'
            ],
            'unknown_roles' => [
                'roles' => ['nonexistent_role'],
                'expectedPermissions' => [],
                'description' => 'Unknown roles should return empty permissions'
            ],
            'empty_roles' => [
                'roles' => [],
                'expectedPermissions' => [],
                'description' => 'Empty roles should return empty permissions'
            ]
        ];
    }

    /**
     * @dataProvider rolePermissionProvider
     */
    public function testGetPermissionsForRolesWithVariousScenarios(
        array $roles,
        array $expectedPermissions,
        string $description
    ): void {
        $this->seedTestData();

        $permissions = $this->repository->getPermissionsForRoles($roles);

        sort($expectedPermissions);
        sort($permissions);

        $this->assertEquals($expectedPermissions, $permissions, $description);
    }

    /**
     * Test caching functionality
     */
    public function testCachingBehavior(): void
    {
        $this->seedTestData();
        $userId = 'admin@example.com';
        $cachedPermissions = ['cached.permission1', 'cached.permission2'];

        // Test cache hit
        $cacheItem = $this->createMock(CacheItemInterface::class);
        $cacheItem->method('isHit')->willReturn(true);
        $cacheItem->method('get')->willReturn($cachedPermissions);
        $this->cache->method('getItem')->willReturn($cacheItem);

        $permissions = $this->repository->getPermissionsForUser($userId);

        $this->assertEquals($cachedPermissions, $permissions);
    }

    public function testCacheMiss(): void
    {
        $this->seedTestData();
        $userId = 'admin@example.com';

        // Mock cache miss
        $cacheItem = $this->createMock(CacheItemInterface::class);
        $cacheItem->method('isHit')->willReturn(false);
        $cacheItem->expects($this->once())->method('set')->willReturnSelf();
        $cacheItem->expects($this->once())->method('expiresAfter')->willReturnSelf();
        
        $this->cache->method('getItem')->willReturn($cacheItem);
        $this->cache->expects($this->once())->method('save');

        $permissions = $this->repository->getPermissionsForUser($userId);

        $this->assertIsArray($permissions);
        $this->assertGreaterThan(0, count($permissions));
    }

    /**
     * Test data modification operations
     */
    public function testBindPermissionToUser(): void
    {
        $userId = 'testuser@example.com';
        $permission = 'test.new_permission';

        $result = $this->repository->bindPermissionToUser($userId, $permission);

        $this->assertTrue($result);

        // Verify permission was added
        $stmt = $this->pdo->prepare("SELECT COUNT(*) FROM user_permissions WHERE user_id = ? AND permission = ?");
        $stmt->execute([$userId, $permission]);
        $count = $stmt->fetchColumn();

        $this->assertEquals(1, $count);
    }

    public function testBindRoleToUser(): void
    {
        $userId = 'testuser@example.com';
        $role = 'test_role';

        $result = $this->repository->bindRoleToUser($userId, $role);

        $this->assertTrue($result);

        // Verify role was added
        $stmt = $this->pdo->prepare("SELECT COUNT(*) FROM user_roles WHERE user_id = ? AND role = ?");
        $stmt->execute([$userId, $role]);
        $count = $stmt->fetchColumn();

        $this->assertEquals(1, $count);
    }

    public function testBindPermissionToRole(): void
    {
        $role = 'test_role';
        $permission = 'test.new_permission';

        $result = $this->repository->bindPermissionToRole($role, $permission);

        $this->assertTrue($result);

        // Verify permission was bound to role
        $stmt = $this->pdo->prepare("SELECT COUNT(*) FROM role_permissions WHERE role = ? AND permission = ?");
        $stmt->execute([$role, $permission]);
        $count = $stmt->fetchColumn();

        $this->assertEquals(1, $count);
    }

    /**
     * Test unbinding operations
     */
    public function testUnbindPermissionFromUser(): void
    {
        $this->seedTestData();

        $result = $this->repository->unbindPermissionFromUser('admin@example.com', 'system.maintenance');

        $this->assertTrue($result);

        // Verify permission was removed
        $stmt = $this->pdo->prepare("SELECT COUNT(*) FROM user_permissions WHERE user_id = ? AND permission = ?");
        $stmt->execute(['admin@example.com', 'system.maintenance']);
        $count = $stmt->fetchColumn();

        $this->assertEquals(0, $count);
    }

    public function testUnbindRoleFromUser(): void
    {
        $this->seedTestData();

        $result = $this->repository->unbindRoleFromUser('admin@example.com', 'super_admin');

        $this->assertTrue($result);

        // Verify role was removed
        $stmt = $this->pdo->prepare("SELECT COUNT(*) FROM user_roles WHERE user_id = ? AND role = ?");
        $stmt->execute(['admin@example.com', 'super_admin']);
        $count = $stmt->fetchColumn();

        $this->assertEquals(0, $count);
    }

    /**
     * Test duplicate prevention
     */
    public function testDuplicatePermissionPrevention(): void
    {
        $userId = 'testuser@example.com';
        $permission = 'test.duplicate_permission';

        // Add permission first time
        $result1 = $this->repository->bindPermissionToUser($userId, $permission);
        $this->assertTrue($result1);

        // Try to add same permission again
        $result2 = $this->repository->bindPermissionToUser($userId, $permission);
        $this->assertTrue($result2); // Should still return true but not create duplicate

        // Verify only one record exists
        $stmt = $this->pdo->prepare("SELECT COUNT(*) FROM user_permissions WHERE user_id = ? AND permission = ?");
        $stmt->execute([$userId, $permission]);
        $count = $stmt->fetchColumn();

        $this->assertEquals(1, $count);
    }

    public function testDuplicateRolePrevention(): void
    {
        $userId = 'testuser@example.com';
        $role = 'test_duplicate_role';

        // Add role first time
        $result1 = $this->repository->bindRoleToUser($userId, $role);
        $this->assertTrue($result1);

        // Try to add same role again
        $result2 = $this->repository->bindRoleToUser($userId, $role);
        $this->assertTrue($result2); // Should still return true but not create duplicate

        // Verify only one record exists
        $stmt = $this->pdo->prepare("SELECT COUNT(*) FROM user_roles WHERE user_id = ? AND role = ?");
        $stmt->execute([$userId, $role]);
        $count = $stmt->fetchColumn();

        $this->assertEquals(1, $count);
    }

    /**
     * Test repository without cache
     */
    public function testRepositoryWithoutCache(): void
    {
        $this->seedTestData();

        // Create repository without cache
        $repository = new class($this->config) extends PdoBindingsRepository {
            private PDO $testPdo;

            public function __construct(DbConfig $config)
            {
                parent::__construct($config, null);
            }

            public function setTestPdo(PDO $pdo): void
            {
                $this->testPdo = $pdo;
            }

            protected function getPdo(): PDO
            {
                return $this->testPdo ?? parent::getPdo();
            }
        };

        $repository->setTestPdo($this->pdo);

        $permissions = $repository->getPermissionsForUser('admin@example.com');

        $this->assertIsArray($permissions);
        $this->assertGreaterThan(0, count($permissions));
        $this->assertContains('system.maintenance', $permissions);
    }

    /**
     * Test clear cache functionality
     */
    public function testClearCache(): void
    {
        $this->cache
            ->expects($this->once())
            ->method('clear')
            ->willReturn(true);

        $result = $this->repository->clearCache();

        $this->assertTrue($result);
    }

    public function testClearCacheWithoutCache(): void
    {
        // Create repository without cache
        $repository = new class($this->config) extends PdoBindingsRepository {
            public function __construct(DbConfig $config)
            {
                parent::__construct($config, null);
            }
        };

        $result = $repository->clearCache();

        $this->assertFalse($result);
    }

    /**
     * Test edge cases and error conditions
     */
    public function testGetPermissionsForEmptyUserId(): void
    {
        $permissions = $this->repository->getPermissionsForUser('');
        $this->assertEquals([], $permissions);
    }

    public function testGetRolesForEmptyUserId(): void
    {
        $roles = $this->repository->getRolesForUser('');
        $this->assertEquals([], $roles);
    }

    /**
     * Test complex permission inheritance scenario
     */
    public function testComplexPermissionInheritance(): void
    {
        $this->seedTestData();

        // Test user with multiple groups and roles
        $this->pdo->exec("
            INSERT OR IGNORE INTO user_groups (user_id, group_id) VALUES 
            ('complex@example.com', 'admin_group'),
            ('complex@example.com', 'editor_group')
        ");

        $this->pdo->exec("
            INSERT OR IGNORE INTO user_permissions (user_id, permission) VALUES 
            ('complex@example.com', 'special.complex_permission')
        ");

        // Mock cache miss
        $cacheItem = $this->createMock(CacheItemInterface::class);
        $cacheItem->method('isHit')->willReturn(false);
        $this->cache->method('getItem')->willReturn($cacheItem);

        $permissions = $this->repository->getPermissionsForUser('complex@example.com');

        // Should have permissions from:
        // 1. Direct assignment: special.complex_permission
        // 2. Admin group: super_admin + manager roles
        // 3. Editor group: editor + content_creator roles
        $expectedPermissions = [
            'special.complex_permission',
            // From super_admin role
            'users.create', 'users.delete', 'users.edit', 'orders.create', 'orders.edit', 'orders.delete', 'orders.view',
            // From manager role
            'reports.view',
            // From editor role
            'content.create', 'content.edit',
            // From content_creator role (content.create is duplicate)
        ];

        // Remove duplicates and sort
        $expectedPermissions = array_unique($expectedPermissions);
        sort($expectedPermissions);
        sort($permissions);

        $this->assertEquals($expectedPermissions, $permissions);
    }
}