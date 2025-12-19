<?php

declare(strict_types=1);

namespace authlib\Auth\Tests;

use PHPUnit\Framework\TestCase;
use authlib\Auth\Core\AuthorizationService;
use authlib\Auth\Contracts\BindingsRepositoryInterface;
use authlib\Auth\Contracts\AuditSinkInterface;
use authlib\Auth\Core\PermissionCache;

/**
 * Test suite for the new AuthorizationService userHasPermission functionality
 */
class NewAuthorizationServiceTest extends TestCase
{
    private AuthorizationService $authorizationService;
    private BindingsRepositoryInterface $mockRepo;
    private AuditSinkInterface $mockAudit;
    private PermissionCache $mockCache;

    protected function setUp(): void
    {
        $this->mockRepo = $this->createMock(BindingsRepositoryInterface::class);
        $this->mockAudit = $this->createMock(AuditSinkInterface::class);
        $this->mockCache = $this->createMock(PermissionCache::class);

        $this->authorizationService = new AuthorizationService(
            $this->mockRepo,
            $this->mockAudit,
            $this->mockCache
        );
    }

    public function testUserHasPermissionReturnsTrueWhenPermissionGranted(): void
    {
        $userId = 'user123';
        $groupIds = ['group1', 'group2'];
        $permission = 'Orders.View';
        $roleIds = [1, 2];
        $permissions = ['Orders.View', 'Orders.Edit'];

        // Mock cache miss
        $this->mockCache
            ->expects($this->once())
            ->method('has')
            ->willReturn(false);

        // Mock repository calls
        $this->mockRepo
            ->expects($this->once())
            ->method('getRolesForGroups')
            ->with($groupIds)
            ->willReturn($roleIds);

        $this->mockRepo
            ->expects($this->once())
            ->method('getPermissionsForRoles')
            ->with($roleIds)
            ->willReturn($permissions);

        // Mock cache set
        $this->mockCache
            ->expects($this->once())
            ->method('set')
            ->with(
                $this->stringContains('perm:user123:Orders.View:'),
                true,
                600
            );

        // Mock audit logging
        $this->mockAudit
            ->expects($this->once())
            ->method('logDecision')
            ->with($userId, $permission, true, [
                'roles' => $roleIds,
                'groups' => $groupIds,
            ]);

        $result = $this->authorizationService->userHasPermission($userId, $groupIds, $permission);

        $this->assertTrue($result);
    }

    public function testUserHasPermissionReturnsFalseWhenPermissionDenied(): void
    {
        $userId = 'user123';
        $groupIds = ['group1', 'group2'];
        $permission = 'Orders.Delete';
        $roleIds = [1, 2];
        $permissions = ['Orders.View', 'Orders.Edit']; // No Delete permission

        // Mock cache miss
        $this->mockCache
            ->expects($this->once())
            ->method('has')
            ->willReturn(false);

        // Mock repository calls
        $this->mockRepo
            ->expects($this->once())
            ->method('getRolesForGroups')
            ->with($groupIds)
            ->willReturn($roleIds);

        $this->mockRepo
            ->expects($this->once())
            ->method('getPermissionsForRoles')
            ->with($roleIds)
            ->willReturn($permissions);

        // Mock cache set with false
        $this->mockCache
            ->expects($this->once())
            ->method('set')
            ->with(
                $this->stringContains('perm:user123:Orders.Delete:'),
                false,
                600
            );

        // Mock audit logging
        $this->mockAudit
            ->expects($this->once())
            ->method('logDecision')
            ->with($userId, $permission, false, [
                'roles' => $roleIds,
                'groups' => $groupIds,
            ]);

        $result = $this->authorizationService->userHasPermission($userId, $groupIds, $permission);

        $this->assertFalse($result);
    }

    public function testUserHasPermissionReturnsCachedResult(): void
    {
        $userId = 'user123';
        $groupIds = ['group1', 'group2'];
        $permission = 'Orders.View';

        // Mock cache hit
        $this->mockCache
            ->expects($this->once())
            ->method('has')
            ->willReturn(true);

        $this->mockCache
            ->expects($this->once())
            ->method('get')
            ->willReturn(true);

        // Repository methods should not be called when cache hits
        $this->mockRepo
            ->expects($this->never())
            ->method('getRolesForGroups');

        $this->mockRepo
            ->expects($this->never())
            ->method('getPermissionsForRoles');

        // Mock audit logging with cache flag
        $this->mockAudit
            ->expects($this->once())
            ->method('logDecision')
            ->with($userId, $permission, true, ['cache' => true]);

        $result = $this->authorizationService->userHasPermission($userId, $groupIds, $permission);

        $this->assertTrue($result);
    }

    public function testUserHasPermissionWithEmptyGroups(): void
    {
        $userId = 'user123';
        $groupIds = [];
        $permission = 'Orders.View';

        // Mock cache miss
        $this->mockCache
            ->expects($this->once())
            ->method('has')
            ->willReturn(false);

        // Mock repository calls with empty arrays
        $this->mockRepo
            ->expects($this->once())
            ->method('getRolesForGroups')
            ->with([])
            ->willReturn([]);

        $this->mockRepo
            ->expects($this->once())
            ->method('getPermissionsForRoles')
            ->with([])
            ->willReturn([]);

        // Mock cache set with false
        $this->mockCache
            ->expects($this->once())
            ->method('set')
            ->with(
                $this->stringContains('perm:user123:Orders.View:'),
                false,
                600
            );

        // Mock audit logging
        $this->mockAudit
            ->expects($this->once())
            ->method('logDecision')
            ->with($userId, $permission, false, [
                'roles' => [],
                'groups' => [],
            ]);

        $result = $this->authorizationService->userHasPermission($userId, $groupIds, $permission);

        $this->assertFalse($result);
    }

    public function testUserHasPermissionGeneratesCorrectCacheKey(): void
    {
        $userId = 'user123';
        $groupIds = ['group1', 'group2'];
        $permission = 'Orders.View';
        $expectedKeyPattern = 'perm:user123:Orders.View:' . md5('group1,group2');

        // Mock cache miss
        $this->mockCache
            ->expects($this->once())
            ->method('has')
            ->with($expectedKeyPattern)
            ->willReturn(false);

        // Mock other dependencies
        $this->mockRepo
            ->method('getRolesForGroups')
            ->willReturn([]);
        $this->mockRepo
            ->method('getPermissionsForRoles')
            ->willReturn([]);
        $this->mockCache
            ->method('set')
            ->with($expectedKeyPattern, false, 600);
        $this->mockAudit
            ->method('logDecision');

        $this->authorizationService->userHasPermission($userId, $groupIds, $permission);
    }
}