<?php

declare(strict_types=1);

namespace authlib\Auth\Tests;

use PHPUnit\Framework\TestCase;
use authlib\Auth\Core\AuthorizationService;
use authlib\Auth\Core\PermissionCache;
use authlib\Auth\Contracts\TokenValidatorInterface;
use authlib\Auth\Contracts\ClaimsExtractorInterface;
use authlib\Auth\Contracts\BindingsRepositoryInterface;
use authlib\Auth\Contracts\AuditSinkInterface;
use authlib\Auth\Core\PolicyEnforcer;
use stdClass;

/**
 * Enhanced test suite for AuthorizationService with comprehensive coverage
 */
class AuthorizationServiceTest extends TestCase
{
    private AuthorizationService $authorizationService;
    private BindingsRepositoryInterface $bindingsRepository;
    private AuditSinkInterface $auditSink;
    private PermissionCache $cache;
    private TokenValidatorInterface $tokenValidator;
    private ClaimsExtractorInterface $claimsExtractor;
    private PolicyEnforcer $policyEnforcer;

    protected function setUp(): void
    {
        $this->bindingsRepository = $this->createMock(BindingsRepositoryInterface::class);
        $this->auditSink = $this->createMock(AuditSinkInterface::class);
        $this->cache = $this->createMock(PermissionCache::class);
        $this->tokenValidator = $this->createMock(TokenValidatorInterface::class);
        $this->claimsExtractor = $this->createMock(ClaimsExtractorInterface::class);
        $this->policyEnforcer = $this->createMock(PolicyEnforcer::class);

        $this->authorizationService = new AuthorizationService(
            repo: $this->bindingsRepository,
            audit: $this->auditSink,
            cache: $this->cache,
            tokenValidator: $this->tokenValidator,
            claimsExtractor: $this->claimsExtractor,
            policyEnforcer: $this->policyEnforcer,
            auditSink: $this->auditSink
        );
    }

    /**
     * Data provider for role/permission resolution testing
     * @return array<string, array{userId: string, permission: string, userPermissions: string[], policyResult: bool, expectedResult: bool, description: string}>
     */
    public static function permissionResolutionProvider(): array
    {
        return [
            'user_has_direct_permission' => [
                'userId' => 'user123',
                'permission' => 'Orders.Edit',
                'userPermissions' => ['Orders.Edit', 'Orders.View'],
                'policyResult' => true,
                'expectedResult' => true,
                'description' => 'User has direct permission and policy allows'
            ],
            'user_lacks_permission' => [
                'userId' => 'user456',
                'permission' => 'Orders.Delete',
                'userPermissions' => ['Orders.View', 'Orders.Edit'],
                'policyResult' => true,
                'expectedResult' => false,
                'description' => 'User lacks the required permission'
            ],
            'user_has_permission_but_policy_denies' => [
                'userId' => 'user789',
                'permission' => 'Orders.Edit',
                'userPermissions' => ['Orders.Edit', 'Orders.View'],
                'policyResult' => false,
                'expectedResult' => false,
                'description' => 'User has permission but policy enforcement denies access'
            ],
            'user_no_permissions' => [
                'userId' => 'user000',
                'permission' => 'Orders.View',
                'userPermissions' => [],
                'policyResult' => true,
                'expectedResult' => false,
                'description' => 'User has no permissions at all'
            ],
            'wildcard_permission' => [
                'userId' => 'admin',
                'permission' => 'Orders.Edit',
                'userPermissions' => ['*', 'Orders.View'],
                'policyResult' => true,
                'expectedResult' => true,
                'description' => 'User has wildcard permission'
            ]
        ];
    }

    /**
     * @dataProvider permissionResolutionProvider
     */
    public function testPermissionResolution(
        string $userId,
        string $permission,
        array $userPermissions,
        bool $policyResult,
        bool $expectedResult,
        string $description
    ): void {
        // Setup repository mock
        $this->bindingsRepository
            ->expects($this->once())
            ->method('getPermissionsForUser')
            ->with($userId)
            ->willReturn($userPermissions);

        // Setup policy enforcer mock if user has permission
        if (in_array($permission, $userPermissions, true) || in_array('*', $userPermissions, true)) {
            $this->policyEnforcer
                ->expects($this->once())
                ->method('enforce')
                ->with($userId, $permission, [])
                ->willReturn($policyResult);
        }

        // Setup audit expectations
        if ($expectedResult) {
            $this->auditSink
                ->expects($this->once())
                ->method('logPermissionGranted')
                ->with($userId, $permission, []);
        } else {
            $this->auditSink
                ->expects($this->once())
                ->method('logPermissionDenied')
                ->with($userId, $permission, []);
        }

        $result = $this->authorizationService->hasPermission($userId, $permission);

        $this->assertEquals($expectedResult, $result, $description);
    }

    /**
     * Data provider for cache testing scenarios
     * @return array<string, array{cacheKey: string, cacheHit: bool, cacheValue: ?bool, expectedCalls: int}>
     */
    public static function cacheScenarioProvider(): array
    {
        return [
            'cache_hit_granted' => [
                'cacheKey' => 'perm:user123:Orders.Edit:d751713988987e9331980363e24189ce',
                'cacheHit' => true,
                'cacheValue' => true,
                'expectedCalls' => 0 // No repository calls when cache hits
            ],
            'cache_hit_denied' => [
                'cacheKey' => 'perm:user456:Orders.Delete:d751713988987e9331980363e24189ce',
                'cacheHit' => true,
                'cacheValue' => false,
                'expectedCalls' => 0
            ],
            'cache_miss' => [
                'cacheKey' => 'perm:user789:Orders.View:d751713988987e9331980363e24189ce',
                'cacheHit' => false,
                'cacheValue' => null,
                'expectedCalls' => 2 // getRolesForGroups + getPermissionsForRoles
            ]
        ];
    }

    /**
     * @dataProvider cacheScenarioProvider
     */
    public function testCacheHitAndMiss(string $cacheKey, bool $cacheHit, ?bool $cacheValue, int $expectedCalls): void
    {
        $userId = 'testuser';
        $groupIds = ['group1', 'group2'];
        $permission = 'Orders.Edit';

        // Setup cache mock
        $this->cache
            ->expects($this->once())
            ->method('has')
            ->willReturn($cacheHit);

        if ($cacheHit) {
            $this->cache
                ->expects($this->once())
                ->method('get')
                ->willReturn($cacheValue);
            
            // No repository calls expected
            $this->bindingsRepository
                ->expects($this->never())
                ->method('getRolesForGroups');
        } else {
            $this->cache
                ->expects($this->once())
                ->method('set')
                ->with($this->isType('string'), $this->isType('boolean'), 600);

            // Repository calls expected
            $this->bindingsRepository
                ->expects($this->once())
                ->method('getRolesForGroups')
                ->with($groupIds)
                ->willReturn(['admin', 'editor']);

            $this->bindingsRepository
                ->expects($this->once())
                ->method('getPermissionsForRoles')
                ->with(['admin', 'editor'])
                ->willReturn(['Orders.Edit', 'Orders.View']);
        }

        // Setup audit expectations
        $this->auditSink
            ->expects($this->once())
            ->method('logDecision')
            ->with(
                $userId,
                $permission,
                $this->isType('boolean'),
                $this->arrayHasKey($cacheHit ? 'cache' : 'roles')
            );

        $result = $this->authorizationService->userHasPermission($userId, $groupIds, $permission);

        $this->assertIsBool($result);
    }

    /**
     * Data provider for role testing scenarios
     * @return array<string, array{userId: string, role: string, userRoles: string[], expectedResult: bool}>
     */
    public static function roleTestingProvider(): array
    {
        return [
            'user_has_role' => [
                'userId' => 'user123',
                'role' => 'admin',
                'userRoles' => ['admin', 'editor'],
                'expectedResult' => true
            ],
            'user_lacks_role' => [
                'userId' => 'user456',
                'role' => 'manager',
                'userRoles' => ['editor', 'viewer'],
                'expectedResult' => false
            ],
            'user_no_roles' => [
                'userId' => 'user789',
                'role' => 'admin',
                'userRoles' => [],
                'expectedResult' => false
            ],
            'case_sensitive_role' => [
                'userId' => 'user000',
                'role' => 'Admin',
                'userRoles' => ['admin', 'editor'],
                'expectedResult' => false
            ]
        ];
    }

    /**
     * @dataProvider roleTestingProvider
     */
    public function testRoleChecking(string $userId, string $role, array $userRoles, bool $expectedResult): void
    {
        $this->bindingsRepository
            ->expects($this->once())
            ->method('getRolesForUser')
            ->with($userId)
            ->willReturn($userRoles);

        $this->auditSink
            ->expects($this->once())
            ->method('logAuthorizationEvent')
            ->with('role_check', $userId, [
                'role' => $role,
                'has_role' => $expectedResult
            ]);

        $result = $this->authorizationService->hasRole($userId, $role);

        $this->assertEquals($expectedResult, $result);
    }

    /**
     * Data provider for token authorization scenarios
     */
    public static function tokenAuthorizationProvider(): array
    {
        return [
            'valid_token_with_permission' => [
                'token' => 'valid.jwt.token',
                'permission' => 'Orders.Edit',
                'payload' => (object)['sub' => 'user123', 'iss' => 'auth.example.com'],
                'claims' => ['user_id' => 'user123', 'roles' => ['admin']],
                'userPermissions' => ['Orders.Edit', 'Orders.View'],
                'policyResult' => true,
                'expectException' => false,
                'expectedResult' => true
            ],
            'valid_token_without_permission' => [
                'token' => 'valid.jwt.token2',
                'permission' => 'Orders.Delete',
                'payload' => (object)['sub' => 'user456', 'iss' => 'auth.example.com'],
                'claims' => ['user_id' => 'user456', 'roles' => ['editor']],
                'userPermissions' => ['Orders.View'],
                'policyResult' => true,
                'expectException' => false,
                'expectedResult' => false
            ],
            'missing_user_id' => [
                'token' => 'valid.jwt.token3',
                'permission' => 'Orders.View',
                'payload' => (object)['iss' => 'auth.example.com'],
                'claims' => ['user_id' => null],
                'userPermissions' => [],
                'policyResult' => true,
                'expectException' => false,
                'expectedResult' => false
            ]
        ];
    }

    /**
     * @dataProvider tokenAuthorizationProvider
     */
    public function testTokenAuthorization(
        string $token,
        string $permission,
        object $payload,
        array $claims,
        array $userPermissions,
        bool $policyResult,
        bool $expectException,
        bool $expectedResult
    ): void {
        // Setup token validator
        $this->tokenValidator
            ->expects($this->once())
            ->method('validate')
            ->with($token)
            ->willReturn($payload);

        // Setup claims extractor
        $this->claimsExtractor
            ->expects($this->once())
            ->method('extractClaims')
            ->with($payload)
            ->willReturn($claims);

        $userId = $claims['user_id'] ?? null;

        if ($userId) {
            // Setup repository mock for user permissions
            $this->bindingsRepository
                ->expects($this->once())
                ->method('getPermissionsForUser')
                ->with($userId)
                ->willReturn($userPermissions);

            // Setup policy enforcer if user has permission
            if (in_array($permission, $userPermissions, true)) {
                $this->policyEnforcer
                    ->expects($this->once())
                    ->method('enforce')
                    ->willReturn($policyResult);
            }

            // Setup audit for authorization event
            $this->auditSink
                ->expects($this->atLeast(1))
                ->method('logAuthorizationEvent');
        } else {
            // Setup audit for security event when user ID is missing
            $this->auditSink
                ->expects($this->once())
                ->method('logSecurityEvent')
                ->with('missing_user_id', $this->isType('array'));
        }

        // Setup audit for token validation
        $this->auditSink
            ->expects($this->once())
            ->method('logTokenEvent')
            ->with('token_valid', $this->isType('string'), $this->isType('array'));

        $result = $this->authorizationService->authorize($token, $permission);

        $this->assertEquals($expectedResult, $result);
    }

    public function testTokenAuthorizationWithInvalidToken(): void
    {
        $token = 'invalid.token';
        $permission = 'Orders.Edit';

        $this->tokenValidator
            ->expects($this->once())
            ->method('validate')
            ->with($token)
            ->willThrowException(new \Exception('Invalid token signature'));

        $this->auditSink
            ->expects($this->once())
            ->method('logTokenEvent')
            ->with('token_invalid', $this->isType('string'), [
                'error' => 'Invalid token signature'
            ]);

        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Token validation failed: Invalid token signature');

        $this->authorizationService->authorize($token, $permission);
    }

    /**
     * Test audit logging is called for all scenarios
     */
    public function testAuditLoggingForAllOperations(): void
    {
        $userId = 'testuser';
        $permission = 'Orders.Edit';

        // Setup mocks for permission check
        $this->bindingsRepository
            ->method('getPermissionsForUser')
            ->willReturn(['Orders.Edit']);

        $this->policyEnforcer
            ->method('enforce')
            ->willReturn(true);

        // Expect audit logging
        $this->auditSink
            ->expects($this->once())
            ->method('logPermissionGranted')
            ->with($userId, $permission, []);

        $this->authorizationService->hasPermission($userId, $permission);
    }

    /**
     * Test multiple permission checking
     */
    public function testHasAnyPermissionReturnsCorrectly(): void
    {
        $userId = 'testuser';
        $permissions = ['Orders.Edit', 'Orders.Delete', 'Orders.Create'];
        $userPermissions = ['Orders.View', 'Orders.Edit']; // Has only one of the requested

        $this->bindingsRepository
            ->expects($this->once())
            ->method('getPermissionsForUser')
            ->with($userId)
            ->willReturn($userPermissions);

        $this->policyEnforcer
            ->expects($this->once())
            ->method('enforce')
            ->willReturn(true);

        $result = $this->authorizationService->hasAnyPermission($userId, $permissions);

        $this->assertTrue($result);
    }

    public function testHasAllPermissionsReturnsCorrectly(): void
    {
        $userId = 'testuser';
        $permissions = ['Orders.Edit', 'Orders.View'];
        $userPermissions = ['Orders.Edit', 'Orders.View', 'Orders.Delete'];

        $this->bindingsRepository
            ->expects($this->exactly(2))
            ->method('getPermissionsForUser')
            ->with($userId)
            ->willReturn($userPermissions);

        $this->policyEnforcer
            ->expects($this->exactly(2))
            ->method('enforce')
            ->willReturn(true);

        $result = $this->authorizationService->hasAllPermissions($userId, $permissions);

        $this->assertTrue($result);
    }

    public function testGetAllPermissionsReturnsRepositoryData(): void
    {
        $userId = 'testuser';
        $expectedPermissions = ['Orders.Edit', 'Orders.View', 'Products.Manage'];

        $this->bindingsRepository
            ->expects($this->once())
            ->method('getPermissionsForUser')
            ->with($userId)
            ->willReturn($expectedPermissions);

        $result = $this->authorizationService->getAllPermissions($userId);

        $this->assertEquals($expectedPermissions, $result);
    }

    public function testGetAllRolesReturnsRepositoryData(): void
    {
        $userId = 'testuser';
        $expectedRoles = ['admin', 'editor', 'viewer'];

        $this->bindingsRepository
            ->expects($this->once())
            ->method('getRolesForUser')
            ->with($userId)
            ->willReturn($expectedRoles);

        $result = $this->authorizationService->getAllRoles($userId);

        $this->assertEquals($expectedRoles, $result);
    }
}