<?php

declare(strict_types=1);

namespace authlib\Auth\Tests;

use PHPUnit\Framework\TestCase;
use authlib\Auth\Auth\OidcTokenValidator;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Cache\CacheItemInterface;
use InvalidArgumentException;
use Exception;

/**
 * Test suite for OidcTokenValidator
 */
class OidcTokenValidatorTest extends TestCase
{
    private string $issuer = 'https://auth.example.com';
    private string $audience = 'test-audience';
    private string $privateKey;
    private string $publicKey;
    private array $staticJwks;

    protected function setUp(): void
    {
        // Generate test RSA key pair
        $keyResource = openssl_pkey_new([
            'digest_alg' => 'sha256',
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        openssl_pkey_export($keyResource, $this->privateKey);
        $keyDetails = openssl_pkey_get_details($keyResource);
        $this->publicKey = $keyDetails['key'];

        $this->staticJwks = [
            'test-kid' => $this->publicKey
        ];
    }

    public function testConstructorWithStaticJwks(): void
    {
        $validator = new OidcTokenValidator(
            $this->issuer,
            $this->audience,
            staticJwks: $this->staticJwks
        );

        $this->assertEquals($this->issuer, $validator->getAcceptedIssuer());
        $this->assertEquals($this->audience, $validator->getAcceptedAudience());
        $this->assertArrayHasKey('test-kid', $validator->getJwks());
    }

    public function testConstructorThrowsExceptionWithoutJwksSource(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Must provide either JWKS URI, file path, or static JWKS array');

        new OidcTokenValidator($this->issuer, $this->audience);
    }

    public function testValidateAndDecodeValidToken(): void
    {
        $validator = new OidcTokenValidator(
            $this->issuer,
            $this->audience,
            staticJwks: $this->staticJwks
        );

        $payload = [
            'iss' => $this->issuer,
            'aud' => $this->audience,
            'sub' => 'user123',
            'exp' => time() + 3600,
            'iat' => time(),
            'groups' => ['admin', 'users']
        ];

        $token = JWT::encode($payload, $this->privateKey, 'RS256', 'test-kid');
        $decodedClaims = $validator->validateAndDecode($token);

        $this->assertEquals($this->issuer, $decodedClaims['iss']);
        $this->assertEquals($this->audience, $decodedClaims['aud']);
        $this->assertEquals('user123', $decodedClaims['sub']);
        $this->assertEquals(['admin', 'users'], $decodedClaims['groups']);
    }

    public function testValidateTokenWithArrayAudience(): void
    {
        $validator = new OidcTokenValidator(
            $this->issuer,
            $this->audience,
            staticJwks: $this->staticJwks
        );

        $payload = [
            'iss' => $this->issuer,
            'aud' => [$this->audience, 'other-audience'],
            'sub' => 'user123',
            'exp' => time() + 3600,
            'iat' => time()
        ];

        $token = JWT::encode($payload, $this->privateKey, 'RS256', 'test-kid');
        $result = $validator->validateAndDecode($token);

        $this->assertEquals('user123', $result['sub']);
    }

    public function testValidateThrowsExceptionForExpiredToken(): void
    {
        $validator = new OidcTokenValidator(
            $this->issuer,
            $this->audience,
            staticJwks: $this->staticJwks
        );

        $payload = [
            'iss' => $this->issuer,
            'aud' => $this->audience,
            'sub' => 'user123',
            'exp' => time() - 3600, // Expired
            'iat' => time() - 7200
        ];

        $token = JWT::encode($payload, $this->privateKey, 'RS256', 'test-kid');

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Token has expired');

        $validator->validateAndDecode($token);
    }

    public function testValidateThrowsExceptionForInvalidIssuer(): void
    {
        $validator = new OidcTokenValidator(
            $this->issuer,
            $this->audience,
            staticJwks: $this->staticJwks
        );

        $payload = [
            'iss' => 'https://wrong-issuer.com',
            'aud' => $this->audience,
            'sub' => 'user123',
            'exp' => time() + 3600,
            'iat' => time()
        ];

        $token = JWT::encode($payload, $this->privateKey, 'RS256', 'test-kid');

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Invalid issuer');

        $validator->validateAndDecode($token);
    }

    public function testValidateThrowsExceptionForInvalidAudience(): void
    {
        $validator = new OidcTokenValidator(
            $this->issuer,
            $this->audience,
            staticJwks: $this->staticJwks
        );

        $payload = [
            'iss' => $this->issuer,
            'aud' => 'wrong-audience',
            'sub' => 'user123',
            'exp' => time() + 3600,
            'iat' => time()
        ];

        $token = JWT::encode($payload, $this->privateKey, 'RS256', 'test-kid');

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Invalid audience');

        $validator->validateAndDecode($token);
    }

    public function testValidateThrowsExceptionForUnknownKid(): void
    {
        $validator = new OidcTokenValidator(
            $this->issuer,
            $this->audience,
            staticJwks: $this->staticJwks
        );

        $payload = [
            'iss' => $this->issuer,
            'aud' => $this->audience,
            'sub' => 'user123',
            'exp' => time() + 3600,
            'iat' => time()
        ];

        $token = JWT::encode($payload, $this->privateKey, 'RS256', 'unknown-kid');

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Unknown key id (kid)');

        $validator->validateAndDecode($token);
    }

    public function testValidateThrowsExceptionForMissingKid(): void
    {
        $validator = new OidcTokenValidator(
            $this->issuer,
            $this->audience,
            staticJwks: $this->staticJwks
        );

        $payload = [
            'iss' => $this->issuer,
            'aud' => $this->audience,
            'sub' => 'user123',
            'exp' => time() + 3600,
            'iat' => time()
        ];

        $token = JWT::encode($payload, $this->privateKey, 'RS256'); // No kid

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Token header missing key ID');

        $validator->validateAndDecode($token);
    }

    public function testIsValidReturnsTrueForValidToken(): void
    {
        $validator = new OidcTokenValidator(
            $this->issuer,
            $this->audience,
            staticJwks: $this->staticJwks
        );

        $payload = [
            'iss' => $this->issuer,
            'aud' => $this->audience,
            'sub' => 'user123',
            'exp' => time() + 3600,
            'iat' => time()
        ];

        $token = JWT::encode($payload, $this->privateKey, 'RS256', 'test-kid');

        $this->assertTrue($validator->isValid($token));
    }

    public function testIsValidReturnsFalseForInvalidToken(): void
    {
        $validator = new OidcTokenValidator(
            $this->issuer,
            $this->audience,
            staticJwks: $this->staticJwks
        );

        $this->assertFalse($validator->isValid('invalid.jwt.token'));
    }

    public function testConstructorWithJwksFile(): void
    {
        $jwksFile = tempnam(sys_get_temp_dir(), 'test_jwks');
        $jwksData = [
            'keys' => [
                [
                    'kid' => 'test-kid',
                    'kty' => 'RSA',
                    'x5c' => [base64_encode($this->publicKey)]
                ]
            ]
        ];
        file_put_contents($jwksFile, json_encode($jwksData));

        try {
            $validator = new OidcTokenValidator(
                $this->issuer,
                $this->audience,
                jwksFilePath: $jwksFile
            );

            $this->assertArrayHasKey('test-kid', $validator->getJwks());
        } finally {
            unlink($jwksFile);
        }
    }

    public function testCacheIntegration(): void
    {
        $mockCache = $this->createMock(CacheItemPoolInterface::class);
        $mockItem = $this->createMock(CacheItemInterface::class);

        $mockCache
            ->expects($this->once())
            ->method('getItem')
            ->willReturn($mockItem);

        $mockItem
            ->expects($this->once())
            ->method('isHit')
            ->willReturn(false);

        $mockItem
            ->expects($this->once())
            ->method('set')
            ->willReturnSelf();

        $mockItem
            ->expects($this->once())
            ->method('expiresAfter')
            ->willReturnSelf();

        $mockCache
            ->expects($this->once())
            ->method('save');

        // This would normally test JWKS URI fetching with cache
        // For this test, we'll just verify cache interaction
        $validator = new OidcTokenValidator(
            $this->issuer,
            $this->audience,
            staticJwks: $this->staticJwks,
            cache: $mockCache
        );

        $this->assertInstanceOf(OidcTokenValidator::class, $validator);
    }

    public function testValidateNotBeforeTime(): void
    {
        $validator = new OidcTokenValidator(
            $this->issuer,
            $this->audience,
            staticJwks: $this->staticJwks
        );

        $payload = [
            'iss' => $this->issuer,
            'aud' => $this->audience,
            'sub' => 'user123',
            'exp' => time() + 3600,
            'nbf' => time() + 1800, // Not valid for another 30 minutes
            'iat' => time()
        ];

        $token = JWT::encode($payload, $this->privateKey, 'RS256', 'test-kid');

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Token not yet valid');

        $validator->validateAndDecode($token);
    }

    public function testClearCache(): void
    {
        $mockCache = $this->createMock(CacheItemPoolInterface::class);
        
        $mockCache
            ->expects($this->once())
            ->method('deleteItem')
            ->willReturn(true);

        $validator = new OidcTokenValidator(
            $this->issuer,
            $this->audience,
            jwksUri: 'https://example.com/.well-known/jwks.json',
            cache: $mockCache
        );

        $result = $validator->clearCache();
        $this->assertTrue($result);
    }
}