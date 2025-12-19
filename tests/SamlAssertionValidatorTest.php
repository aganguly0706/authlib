<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use authlib\Auth\Auth\SamlAssertionValidator;

class SamlAssertionValidatorTest extends TestCase
{
    private SamlAssertionValidator $validator;
    
    protected function setUp(): void
    {
        $config = [
            'entity_id' => 'test-sp',
            'certificate_fingerprints' => ['ABC123', 'DEF456'],
            'issuer' => 'test-idp',
            'max_assertion_age' => 3600,
            'clock_skew' => 300
        ];
        $this->validator = new SamlAssertionValidator($config);
    }

    public function testValidSamlAssertion(): void
    {
        $validAssertion = [
            'iss' => 'test-idp',
            'aud' => 'test-sp',
            'sub' => 'user123',
            'iat' => time() - 100,
            'exp' => time() + 3500,
            'name_id_format' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
            'session_index' => 'session_123',
            'acr' => 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
            'auth_time' => time() - 100,
            'groups' => ['admin', 'users'],
            'roles' => ['manager'],
            'email' => 'user123@example.com',
            'name' => 'Test User'
        ];
        
        $claims = $this->validator->validate(base64_encode(json_encode($validAssertion)));
        
        $this->assertEquals('test-idp', $claims->iss);
        $this->assertEquals('test-sp', $claims->aud);
        $this->assertEquals('user123', $claims->sub);
        $this->assertEquals(['admin', 'users'], $claims->groups);
        $this->assertEquals(['manager'], $claims->roles);
    }

    public function testExpiredAssertion(): void
    {
        $expiredAssertion = [
            'iss' => 'test-idp',
            'aud' => 'test-sp',
            'sub' => 'user123',
            'iat' => time() - 4000,
            'exp' => time() - 100, // Expired
            'name_id_format' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
            'session_index' => 'session_123'
        ];
        
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('SAML assertion has expired');
        
        $this->validator->validate(base64_encode(json_encode($expiredAssertion)));
    }

    public function testInvalidIssuer(): void
    {
        $invalidAssertion = [
            'iss' => 'wrong-idp',
            'aud' => 'test-sp',
            'sub' => 'user123',
            'iat' => time() - 100,
            'exp' => time() + 3500,
            'name_id_format' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
        ];
        
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Invalid issuer');
        
        $this->validator->validate(base64_encode(json_encode($invalidAssertion)));
    }

    public function testInvalidAudience(): void
    {
        $invalidAssertion = [
            'iss' => 'test-idp',
            'aud' => 'wrong-sp',
            'sub' => 'user123',
            'iat' => time() - 100,
            'exp' => time() + 3500,
            'name_id_format' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
        ];
        
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Invalid audience');
        
        $this->validator->validate(base64_encode(json_encode($invalidAssertion)));
    }

    public function testMissingRequiredClaims(): void
    {
        $invalidAssertion = [
            'iss' => 'test-idp',
            'aud' => 'test-sp',
            // Missing 'sub' claim
            'iat' => time() - 100,
            'exp' => time() + 3500
        ];
        
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Missing required claims');
        
        $this->validator->validate(base64_encode(json_encode($invalidAssertion)));
    }

    public function testFutureAssertion(): void
    {
        $futureAssertion = [
            'iss' => 'test-idp',
            'aud' => 'test-sp',
            'sub' => 'user123',
            'iat' => time() + 1000, // Future timestamp
            'exp' => time() + 4000,
            'name_id_format' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
        ];
        
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('SAML assertion not yet valid');
        
        $this->validator->validate(base64_encode(json_encode($futureAssertion)));
    }

    public function testClockSkewTolerance(): void
    {
        // Assertion that would be invalid without clock skew tolerance
        $assertion = [
            'iss' => 'test-idp',
            'aud' => 'test-sp',
            'sub' => 'user123',
            'iat' => time() + 200, // Slightly in future, but within clock skew
            'exp' => time() + 3500,
            'name_id_format' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
        ];
        
        $claims = $this->validator->validate(base64_encode(json_encode($assertion)));
        $this->assertEquals('user123', $claims->sub);
    }

    public function testSamlSpecificClaims(): void
    {
        $samlAssertion = [
            'iss' => 'test-idp',
            'aud' => 'test-sp',
            'sub' => 'user123',
            'iat' => time() - 100,
            'exp' => time() + 3500,
            'name_id_format' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
            'session_index' => 'unique_session_123',
            'acr' => 'urn:oasis:names:tc:SAML:2.0:ac:classes:X509',
            'auth_time' => time() - 100,
            'memberof' => ['CN=Admins,OU=Groups,DC=company,DC=com'],
            'http://schemas.microsoft.com/ws/2008/06/identity/claims/role' => ['Administrator']
        ];
        
        $claims = $this->validator->validate(base64_encode(json_encode($samlAssertion)));
        
        $this->assertEquals('urn:oasis:names:tc:SAML:2.0:nameid-format:persistent', $claims->name_id_format);
        $this->assertEquals('unique_session_123', $claims->session_index);
        $this->assertEquals('urn:oasis:names:tc:SAML:2.0:ac:classes:X509', $claims->acr);
        $this->assertNotNull($claims->auth_time);
    }

    public function testInvalidJsonFormat(): void
    {
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Invalid SAML assertion format');
        
        $this->validator->validate(base64_encode('invalid json'));
    }

    public function testValidationWithCustomConfig(): void
    {
        $customConfig = [
            'entity_id' => 'custom-sp',
            'issuer' => 'custom-idp',
            'max_assertion_age' => 1800, // 30 minutes
            'clock_skew' => 60 // 1 minute
        ];
        
        $customValidator = new SamlAssertionValidator($customConfig);
        
        $assertion = [
            'iss' => 'custom-idp',
            'aud' => 'custom-sp',
            'sub' => 'user456',
            'iat' => time() - 100,
            'exp' => time() + 1700,
            'name_id_format' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
        ];
        
        $claims = $customValidator->validate(base64_encode(json_encode($assertion)));
        $this->assertEquals('user456', $claims->sub);
    }
}