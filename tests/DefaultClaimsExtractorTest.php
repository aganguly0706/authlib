<?php

declare(strict_types=1);

namespace authlib\Auth\Tests;

use PHPUnit\Framework\TestCase;
use authlib\Auth\Auth\DefaultClaimsExtractor;
use InvalidArgumentException;
use stdClass;

/**
 * Test suite for DefaultClaimsExtractor
 */
class DefaultClaimsExtractorTest extends TestCase
{
    private DefaultClaimsExtractor $extractor;

    protected function setUp(): void
    {
        $this->extractor = new DefaultClaimsExtractor();
    }

    public function testExtractGroupsFromArrayClaim(): void
    {
        $claims = [
            'groups' => ['group1', 'group2', 'group3']
        ];

        $result = $this->extractor->extractGroups($claims);

        $this->assertEquals(['group1', 'group2', 'group3'], $result);
    }

    public function testExtractGroupsFromRolesClaim(): void
    {
        $claims = [
            'roles' => ['admin', 'editor', 'user']
        ];

        $result = $this->extractor->extractGroups($claims);

        $this->assertEquals(['admin', 'editor', 'user'], $result);
    }

    public function testExtractGroupsFromMemberOfClaim(): void
    {
        $claims = [
            'memberOf' => ['cn=admin,ou=groups', 'cn=users,ou=groups']
        ];

        $result = $this->extractor->extractGroups($claims);

        $this->assertEquals(['cn=admin,ou=groups', 'cn=users,ou=groups'], $result);
    }

    public function testExtractGroupsFromStringSingleValue(): void
    {
        $claims = [
            'groups' => 'single-group'
        ];

        $result = $this->extractor->extractGroups($claims);

        $this->assertEquals(['single-group'], $result);
    }

    public function testExtractGroupsReturnsEmptyWhenNoClaims(): void
    {
        $claims = [];

        $result = $this->extractor->extractGroups($claims);

        $this->assertEquals([], $result);
    }

    public function testExtractUserIdFromSubClaim(): void
    {
        $claims = [
            'sub' => 'user123'
        ];

        $result = $this->extractor->extractUserId($claims);

        $this->assertEquals('user123', $result);
    }

    public function testExtractUserIdFromPreferredUsernameClaim(): void
    {
        $claims = [
            'preferred_username' => 'john.doe@company.com'
        ];

        $result = $this->extractor->extractUserId($claims);

        $this->assertEquals('john.doe@company.com', $result);
    }

    public function testExtractUserIdFromUserIdClaim(): void
    {
        $claims = [
            'user_id' => 'uid_12345'
        ];

        $result = $this->extractor->extractUserId($claims);

        $this->assertEquals('uid_12345', $result);
    }

    public function testExtractUserIdThrowsExceptionWhenMissing(): void
    {
        $claims = [
            'other_claim' => 'value'
        ];

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unable to extract user ID from token claims');

        $this->extractor->extractUserId($claims);
    }

    public function testExtractUserIdPrioritizesSubOverOtherClaims(): void
    {
        $claims = [
            'sub' => 'subject_user',
            'preferred_username' => 'preferred_user',
            'user_id' => 'userid_user'
        ];

        $result = $this->extractor->extractUserId($claims);

        $this->assertEquals('subject_user', $result);
    }

    public function testExtractClaimsFromPayload(): void
    {
        $payload = new stdClass();
        $payload->sub = 'user123';
        $payload->roles = ['admin', 'user'];
        $payload->permissions = ['read', 'write'];
        $payload->email = 'user@example.com';
        $payload->name = 'Test User';
        $payload->custom_claim = 'custom_value';

        $result = $this->extractor->extractClaims($payload);

        $this->assertEquals('user123', $result['user_id']);
        $this->assertEquals(['admin', 'user'], $result['roles']);
        $this->assertEquals(['read', 'write'], $result['permissions']);
        $this->assertEquals('user@example.com', $result['email']);
        $this->assertEquals('Test User', $result['name']);
        $this->assertArrayHasKey('custom', $result);
        $this->assertEquals('custom_value', $result['custom']['custom_claim']);
    }

    public function testGetRolesHandlesStringValue(): void
    {
        $payload = new stdClass();
        $payload->roles = 'admin';

        $result = $this->extractor->getRoles($payload);

        $this->assertEquals(['admin'], $result);
    }

    public function testGetPermissionsHandlesStringValue(): void
    {
        $payload = new stdClass();
        $payload->permissions = 'read';

        $result = $this->extractor->getPermissions($payload);

        $this->assertEquals(['read'], $result);
    }

    public function testGetCustomClaimsFiltersStandardClaims(): void
    {
        $payload = new stdClass();
        $payload->sub = 'user123';
        $payload->iss = 'issuer';
        $payload->aud = 'audience';
        $payload->exp = 1234567890;
        $payload->roles = ['admin'];
        $payload->permissions = ['read'];
        $payload->email = 'user@example.com';
        $payload->name = 'Test User';
        $payload->custom_field1 = 'value1';
        $payload->custom_field2 = 'value2';

        $result = $this->extractor->getCustomClaims($payload);

        $this->assertArrayNotHasKey('sub', $result);
        $this->assertArrayNotHasKey('iss', $result);
        $this->assertArrayNotHasKey('aud', $result);
        $this->assertArrayNotHasKey('exp', $result);
        $this->assertArrayNotHasKey('roles', $result);
        $this->assertArrayNotHasKey('permissions', $result);
        $this->assertArrayNotHasKey('email', $result);
        $this->assertArrayNotHasKey('name', $result);
        $this->assertArrayHasKey('custom_field1', $result);
        $this->assertArrayHasKey('custom_field2', $result);
        $this->assertEquals('value1', $result['custom_field1']);
        $this->assertEquals('value2', $result['custom_field2']);
    }

    public function testExtractorWithCustomConfiguration(): void
    {
        $customConfig = [
            'user_id_claim' => 'username',
            'roles_claim' => 'user_roles',
            'permissions_claim' => 'user_permissions',
        ];

        $extractor = new DefaultClaimsExtractor($customConfig);

        $payload = new stdClass();
        $payload->username = 'custom_user';
        $payload->user_roles = ['custom_role'];
        $payload->user_permissions = ['custom_permission'];

        $result = $extractor->extractClaims($payload);

        $this->assertEquals('custom_user', $result['user_id']);
        $this->assertEquals(['custom_role'], $result['roles']);
        $this->assertEquals(['custom_permission'], $result['permissions']);
    }
}