<?php

declare(strict_types=1);

namespace authlib\Auth\Tests;

use PHPUnit\Framework\TestCase;
use authlib\Auth\Core\PolicyEnforcer;
use authlib\Auth\Contracts\TokenValidatorInterface;
use authlib\Auth\Contracts\ClaimsExtractorInterface;
use authlib\Auth\Contracts\AuthorizationServiceInterface;

/**
 * Enhanced test suite for PolicyEnforcer with comprehensive denial and grant path testing
 */
class PolicyEnforcerTest extends TestCase
{
    private PolicyEnforcer $policyEnforcer;
    private TokenValidatorInterface $mockValidator;
    private ClaimsExtractorInterface $mockClaimsExtractor;
    private AuthorizationServiceInterface $mockAuthService;

    protected function setUp(): void
    {
        $this->mockValidator = $this->createMock(TokenValidatorInterface::class);
        $this->mockClaimsExtractor = $this->createMock(ClaimsExtractorInterface::class);
        $this->mockAuthService = $this->createMock(AuthorizationServiceInterface::class);

        $this->policyEnforcer = new PolicyEnforcer(
            $this->mockValidator,
            $this->mockClaimsExtractor,
            $this->mockAuthService
        );
    }

    /**
     * Data provider for permission requirement scenarios
     * @return array<string, array{jwt: string, permission: string, claims: array, groups: array, userId: string, authResult: bool, expectedResult: bool, description: string}>
     */
    public static function permissionRequirementProvider(): array
    {
        return [
            'admin_grants_orders_edit' => [
                'jwt' => 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.admin.token',
                'permission' => 'Orders.Edit',
                'claims' => ['sub' => 'admin@example.com', 'roles' => ['admin'], 'groups' => ['admin_group']],
                'groups' => ['admin_group'],
                'userId' => 'admin@example.com',
                'authResult' => true,
                'expectedResult' => true,
                'description' => 'Admin user should be granted Orders.Edit permission'
            ],
            'editor_denied_orders_delete' => [
                'jwt' => 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.editor.token',
                'permission' => 'Orders.Delete',
                'claims' => ['sub' => 'editor@example.com', 'roles' => ['editor'], 'groups' => ['editor_group']],
                'groups' => ['editor_group'],
                'userId' => 'editor@example.com',
                'authResult' => false,
                'expectedResult' => false,
                'description' => 'Editor user should be denied Orders.Delete permission'
            ],
            'viewer_denied_orders_create' => [
                'jwt' => 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.viewer.token',
                'permission' => 'Orders.Create',
                'claims' => ['sub' => 'viewer@example.com', 'roles' => ['viewer'], 'groups' => ['viewer_group']],
                'groups' => ['viewer_group'],
                'userId' => 'viewer@example.com',
                'authResult' => false,
                'expectedResult' => false,
                'description' => 'Viewer user should be denied Orders.Create permission'
            ],
            'user_no_groups' => [
                'jwt' => 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.nogroup.token',
                'permission' => 'Orders.View',
                'claims' => ['sub' => 'nogroup@example.com', 'roles' => [], 'groups' => []],
                'groups' => [],
                'userId' => 'nogroup@example.com',
                'authResult' => false,
                'expectedResult' => false,
                'description' => 'User with no groups should be denied access'
            ],
            'unknown_group_user' => [
                'jwt' => 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.unknown.token',
                'permission' => 'Orders.View',
                'claims' => ['sub' => 'unknown@example.com', 'roles' => ['unknown'], 'groups' => ['unknown_group']],
                'groups' => ['unknown_group'],
                'userId' => 'unknown@example.com',
                'authResult' => false,
                'expectedResult' => false,
                'description' => 'User with unknown groups should be denied access'
            ]
        ];
    }

    /**
     * @dataProvider permissionRequirementProvider
     */
    public function testRequirePermissionWithVariousScenarios(
        string $jwt,
        string $permission,
        array $claims,
        array $groups,
        string $userId,
        bool $authResult,
        bool $expectedResult,
        string $description
    ): void {
        // Mock token validation
        $this->mockValidator
            ->expects($this->once())
            ->method('validateAndDecode')
            ->with($jwt)
            ->willReturn($claims);

        // Mock claims extraction
        $this->mockClaimsExtractor
            ->expects($this->once())
            ->method('extractGroups')
            ->with($claims)
            ->willReturn($groups);

        $this->mockClaimsExtractor
            ->expects($this->once())
            ->method('extractUserId')
            ->with($claims)
            ->willReturn($userId);

        // Mock authorization check
        $this->mockAuthService
            ->expects($this->once())
            ->method('userHasPermission')
            ->with($userId, $groups, $permission)
            ->willReturn($authResult);

        $result = $this->policyEnforcer->requirePermission($jwt, $permission);

        $this->assertEquals($expectedResult, $result, $description);
    }

    /**
     * Data provider for policy enforcement scenarios
     * @return array<string, array{policies: array, userId: string, permission: string, context: array, expectedResult: bool, description: string}>
     */
    public static function policyEnforcementProvider(): array
    {
        return [
            'all_policies_pass' => [
                'policies' => [
                    function() { return true; },
                    function() { return true; },
                    function() { return true; }
                ],
                'userId' => 'user123',
                'permission' => 'Orders.Edit',
                'context' => ['ip_address' => '192.168.1.100'],
                'expectedResult' => true,
                'description' => 'All policies pass, should grant access'
            ],
            'first_policy_fails' => [
                'policies' => [
                    function() { return false; },
                    function() { return true; },
                    function() { return true; }
                ],
                'userId' => 'user456',
                'permission' => 'Orders.Edit',
                'context' => ['ip_address' => '10.0.0.50'],
                'expectedResult' => false,
                'description' => 'First policy fails, should deny access'
            ],
            'middle_policy_fails' => [
                'policies' => [
                    function() { return true; },
                    function() { return false; },
                    function() { return true; }
                ],
                'userId' => 'user789',
                'permission' => 'Orders.View',
                'context' => ['ip_address' => '172.16.0.10'],
                'expectedResult' => false,
                'description' => 'Middle policy fails, should deny access'
            ],
            'last_policy_fails' => [
                'policies' => [
                    function() { return true; },
                    function() { return true; },
                    function() { return false; }
                ],
                'userId' => 'user000',
                'permission' => 'Orders.Delete',
                'context' => ['ip_address' => '203.0.113.10'],
                'expectedResult' => false,
                'description' => 'Last policy fails, should deny access'
            ],
            'no_policies' => [
                'policies' => [],
                'userId' => 'user111',
                'permission' => 'Orders.Create',
                'context' => ['ip_address' => '198.51.100.10'],
                'expectedResult' => true,
                'description' => 'No policies to evaluate, should grant access'
            ],
            'policy_throws_exception' => [
                'policies' => [
                    function() { return true; },
                    function() { throw new \Exception('Policy evaluation failed'); },
                    function() { return true; }
                ],
                'userId' => 'user222',
                'permission' => 'Orders.View',
                'context' => ['ip_address' => '203.0.113.20'],
                'expectedResult' => false,
                'description' => 'Policy throws exception, should deny access'
            ]
        ];
    }

    /**
     * @dataProvider policyEnforcementProvider
     */
    public function testPolicyEnforcementWithVariousScenarios(
        array $policies,
        string $userId,
        string $permission,
        array $context,
        bool $expectedResult,
        string $description
    ): void {
        $enforcer = new PolicyEnforcer(
            $this->mockValidator,
            $this->mockClaimsExtractor,
            $this->mockAuthService,
            $policies
        );

        $result = $enforcer->enforce($userId, $permission, $context);

        $this->assertEquals($expectedResult, $result, $description);
    }

    /**
     * Data provider for time-based policy testing
     * @return array<string, array{startTime: string, endTime: string, currentTime: string, timezone: string, expectedResult: bool}>
     */
    public static function timeBasedPolicyProvider(): array
    {
        return [
            'within_working_hours' => [
                'startTime' => '09:00',
                'endTime' => '17:00',
                'currentTime' => '14:30',
                'timezone' => 'UTC',
                'expectedResult' => true
            ],
            'before_working_hours' => [
                'startTime' => '09:00',
                'endTime' => '17:00',
                'currentTime' => '08:30',
                'timezone' => 'UTC',
                'expectedResult' => false
            ],
            'after_working_hours' => [
                'startTime' => '09:00',
                'endTime' => '17:00',
                'currentTime' => '18:30',
                'timezone' => 'UTC',
                'expectedResult' => false
            ],
            'at_start_time' => [
                'startTime' => '09:00',
                'endTime' => '17:00',
                'currentTime' => '09:00',
                'timezone' => 'UTC',
                'expectedResult' => true
            ],
            'at_end_time' => [
                'startTime' => '09:00',
                'endTime' => '17:00',
                'currentTime' => '17:00',
                'timezone' => 'UTC',
                'expectedResult' => true
            ]
        ];
    }

    /**
     * @dataProvider timeBasedPolicyProvider
     */
    public function testTimeBasedPolicyWithVariousTimes(
        string $startTime,
        string $endTime,
        string $currentTime,
        string $timezone,
        bool $expectedResult
    ): void {
        // Mock the current time for testing
        $mockCurrentTime = \DateTime::createFromFormat('H:i', $currentTime, new \DateTimeZone($timezone));
        
        // Create a custom time-based policy that uses our mock time
        $policy = function() use ($startTime, $endTime, $timezone, $mockCurrentTime) {
            $start = \DateTime::createFromFormat('H:i', $startTime, new \DateTimeZone($timezone));
            $end = \DateTime::createFromFormat('H:i', $endTime, new \DateTimeZone($timezone));

            return $mockCurrentTime >= $start && $mockCurrentTime <= $end;
        };

        $result = $policy('user123', 'Orders.View', []);

        $this->assertEquals($expectedResult, $result);
    }

    /**
     * Data provider for IP-based policy testing
     * @return array<string, array{allowedIps: array, userIp: ?string, expectedResult: bool, description: string}>
     */
    public static function ipBasedPolicyProvider(): array
    {
        return [
            'exact_ip_match' => [
                'allowedIps' => ['192.168.1.100', '10.0.0.50'],
                'userIp' => '192.168.1.100',
                'expectedResult' => true,
                'description' => 'Exact IP match should allow access'
            ],
            'cidr_range_match' => [
                'allowedIps' => ['192.168.1.0/24', '10.0.0.0/8'],
                'userIp' => '192.168.1.150',
                'expectedResult' => true,
                'description' => 'IP within CIDR range should allow access'
            ],
            'ip_not_in_list' => [
                'allowedIps' => ['192.168.1.100', '10.0.0.50'],
                'userIp' => '203.0.113.100',
                'expectedResult' => false,
                'description' => 'IP not in allowed list should deny access'
            ],
            'ip_outside_cidr_range' => [
                'allowedIps' => ['192.168.1.0/24'],
                'userIp' => '192.168.2.100',
                'expectedResult' => false,
                'description' => 'IP outside CIDR range should deny access'
            ],
            'missing_ip_address' => [
                'allowedIps' => ['192.168.1.100'],
                'userIp' => null,
                'expectedResult' => false,
                'description' => 'Missing IP address should deny access'
            ],
            'empty_allowed_ips' => [
                'allowedIps' => [],
                'userIp' => '192.168.1.100',
                'expectedResult' => false,
                'description' => 'Empty allowed IPs list should deny access'
            ]
        ];
    }

    /**
     * @dataProvider ipBasedPolicyProvider
     */
    public function testIpBasedPolicyWithVariousScenarios(
        array $allowedIps,
        ?string $userIp,
        bool $expectedResult,
        string $description
    ): void {
        $policy = PolicyEnforcer::ipBasedPolicy($allowedIps);

        $context = $userIp ? ['ip_address' => $userIp] : [];
        $result = $policy('user123', 'Orders.View', $context);

        $this->assertEquals($expectedResult, $result, $description);
    }

    /**
     * Data provider for resource ownership policy testing
     * @return array<string, array{userId: string, ownerId: ?string, resourceId: string, expectedResult: bool, description: string}>
     */
    public static function resourceOwnershipProvider(): array
    {
        return [
            'owner_access_granted' => [
                'userId' => 'user123',
                'ownerId' => 'user123',
                'resourceId' => 'order_456',
                'expectedResult' => true,
                'description' => 'Resource owner should be granted access'
            ],
            'non_owner_access_denied' => [
                'userId' => 'user123',
                'ownerId' => 'user456',
                'resourceId' => 'order_789',
                'expectedResult' => false,
                'description' => 'Non-owner should be denied access'
            ],
            'missing_owner_id' => [
                'userId' => 'user123',
                'ownerId' => null,
                'resourceId' => 'order_000',
                'expectedResult' => false,
                'description' => 'Missing owner ID should deny access'
            ],
            'empty_owner_id' => [
                'userId' => 'user123',
                'ownerId' => '',
                'resourceId' => 'order_111',
                'expectedResult' => false,
                'description' => 'Empty owner ID should deny access'
            ]
        ];
    }

    /**
     * @dataProvider resourceOwnershipProvider
     */
    public function testResourceOwnershipPolicyWithVariousScenarios(
        string $userId,
        ?string $ownerId,
        string $resourceId,
        bool $expectedResult,
        string $description
    ): void {
        $policy = PolicyEnforcer::resourceOwnershipPolicy('resource_id', 'owner_id');

        $context = [
            'resource_id' => $resourceId,
            'owner_id' => $ownerId
        ];

        $result = $policy($userId, 'Orders.Edit', $context);

        $this->assertEquals($expectedResult, $result, $description);
    }

    /**
     * Test invalid token scenarios
     */
    public function testRequirePermissionWithInvalidTokens(): void
    {
        $invalidTokens = [
            'expired.jwt.token' => 'Token has expired',
            'malformed.token' => 'Invalid token format',
            'tampered.jwt.signature' => 'Token signature invalid'
        ];

        foreach ($invalidTokens as $token => $errorMessage) {
            $this->mockValidator
                ->expects($this->once())
                ->method('validateAndDecode')
                ->with($token)
                ->willThrowException(new \Exception($errorMessage));

            $this->expectException(\Exception::class);
            $this->expectExceptionMessage($errorMessage);

            $this->policyEnforcer->requirePermission($token, 'Orders.View');

            // Reset expectations for next iteration
            $this->setUp();
        }
    }

    /**
     * Test policy management methods
     */
    public function testPolicyManagement(): void
    {
        $policy1 = function() { return true; };
        $policy2 = function() { return false; };
        $policy3 = function() { return true; };

        // Test adding single policy
        $this->policyEnforcer->addPolicy($policy1);
        $this->assertCount(1, $this->policyEnforcer->getPolicies());

        // Test adding multiple policies
        $this->policyEnforcer->addPolicies([$policy2, $policy3]);
        $this->assertCount(3, $this->policyEnforcer->getPolicies());

        // Test clearing policies
        $this->policyEnforcer->clearPolicies();
        $this->assertCount(0, $this->policyEnforcer->getPolicies());
    }

    /**
     * Test getClaims method with various token scenarios
     */
    public function testGetClaimsWithValidAndInvalidTokens(): void
    {
        $validToken = 'valid.jwt.token';
        $invalidToken = 'invalid.jwt.token';
        $expectedClaims = ['sub' => 'user123', 'roles' => ['admin']];

        // Test valid token
        $this->mockValidator
            ->expects($this->once())
            ->method('validateAndDecode')
            ->with($validToken)
            ->willReturn($expectedClaims);

        $result = $this->policyEnforcer->getClaims($validToken);
        $this->assertEquals($expectedClaims, $result);

        // Reset mocks
        $this->setUp();

        // Test invalid token
        $this->mockValidator
            ->expects($this->once())
            ->method('validateAndDecode')
            ->with($invalidToken)
            ->willThrowException(new \Exception('Invalid token'));

        $result = $this->policyEnforcer->getClaims($invalidToken);
        $this->assertNull($result);
    }

    /**
     * Test complex policy combinations
     */
    public function testComplexPolicyCombinations(): void
    {
        // IP-based policy: allow only internal network
        $ipPolicy = PolicyEnforcer::ipBasedPolicy(['192.168.0.0/16', '10.0.0.0/8']);
        
        // Time-based policy: business hours only
        $timePolicy = function() {
            $now = new \DateTime('14:30'); // Simulate 2:30 PM
            $start = \DateTime::createFromFormat('H:i', '09:00');
            $end = \DateTime::createFromFormat('H:i', '17:00');
            return $now >= $start && $now <= $end;
        };
        
        // Resource ownership policy
        $ownershipPolicy = PolicyEnforcer::resourceOwnershipPolicy();

        $enforcer = new PolicyEnforcer(
            $this->mockValidator,
            $this->mockClaimsExtractor,
            $this->mockAuthService,
            [$ipPolicy, $timePolicy, $ownershipPolicy]
        );

        // Test scenario: valid IP, business hours, but wrong owner
        $context = [
            'ip_address' => '192.168.1.100',  // Valid IP
            'resource_id' => 'order_123',
            'owner_id' => 'user456'  // Different owner
        ];

        $result = $enforcer->enforce('user123', 'Orders.Edit', $context);
        $this->assertFalse($result, 'Should deny when ownership policy fails');

        // Test scenario: valid IP, business hours, correct owner
        $context['owner_id'] = 'user123';  // Correct owner
        $result = $enforcer->enforce('user123', 'Orders.Edit', $context);
        $this->assertTrue($result, 'Should grant when all policies pass');
    }
}