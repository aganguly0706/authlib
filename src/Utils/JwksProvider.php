<?php

declare(strict_types=1);

namespace authlib\Auth\Utils;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use Psr\Cache\CacheItemPoolInterface;
use InvalidArgumentException;

/**
 * JWKS (JSON Web Key Set) provider for fetching and caching public keys
 */
class JwksProvider
{
    private Client $httpClient;

    public function __construct(
        private string $jwksUri,
        private ?CacheItemPoolInterface $cache = null,
        private int $cacheTtl = 3600,
        ?Client $httpClient = null
    ) {
        $this->httpClient = $httpClient ?? new Client([
            'timeout' => 10,
            'connect_timeout' => 5,
        ]);
    }

    /**
     * Get a public key by key ID
     *
     * @param string $keyId The key ID (kid)
     * @return string|null The public key in PEM format
     * @throws \Exception When key fetching fails
     */
    public function getKey(string $keyId): ?string
    {
        $jwks = $this->getJwks();
        
        foreach ($jwks['keys'] ?? [] as $key) {
            if (($key['kid'] ?? '') === $keyId) {
                return $this->convertKeyToPem($key);
            }
        }

        return null;
    }

    /**
     * Get all keys from JWKS
     *
     * @return array<string, string> Array of key ID => PEM key pairs
     * @throws \Exception When JWKS fetching fails
     */
    public function getAllKeys(): array
    {
        $jwks = $this->getJwks();
        $keys = [];
        
        foreach ($jwks['keys'] ?? [] as $key) {
            if (isset($key['kid'])) {
                $keys[$key['kid']] = $this->convertKeyToPem($key);
            }
        }

        return $keys;
    }

    /**
     * Refresh the JWKS cache
     *
     * @return bool Success status
     */
    public function refreshCache(): bool
    {
        if ($this->cache) {
            $this->cache->deleteItem($this->getCacheKey());
        }
        
        try {
            $this->getJwks();
            return true;
        } catch (\Exception) {
            return false;
        }
    }

    /**
     * Get JWKS data with caching
     *
     * @return array The JWKS data
     * @throws \Exception When fetching fails
     */
    private function getJwks(): array
    {
        $cacheKey = $this->getCacheKey();
        
        if ($this->cache) {
            $item = $this->cache->getItem($cacheKey);
            if ($item->isHit()) {
                return $item->get();
            }
        }

        try {
            $response = $this->httpClient->get($this->jwksUri, [
                'headers' => [
                    'Accept' => 'application/json',
                    'User-Agent' => 'AuthLib JWKS Client/1.0',
                ],
            ]);

            if ($response->getStatusCode() !== 200) {
                throw new \Exception('Failed to fetch JWKS: HTTP ' . $response->getStatusCode());
            }

            $jwks = json_decode($response->getBody()->getContents(), true);
            
            if (json_last_error() !== JSON_ERROR_NONE) {
                throw new \Exception('Invalid JSON in JWKS response: ' . json_last_error_msg());
            }

            if ($this->cache) {
                $item->set($jwks)->expiresAfter($this->cacheTtl);
                $this->cache->save($item);
            }

            return $jwks;

        } catch (GuzzleException $e) {
            throw new \Exception('Failed to fetch JWKS: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * Convert JWK to PEM format
     *
     * @param array $jwk The JSON Web Key
     * @return string The PEM formatted key
     * @throws InvalidArgumentException When key format is unsupported
     */
    private function convertKeyToPem(array $jwk): string
    {
        if (!isset($jwk['kty'])) {
            throw new InvalidArgumentException('Missing key type (kty) in JWK');
        }

        switch ($jwk['kty']) {
            case 'RSA':
                return $this->convertRsaKeyToPem($jwk);
            case 'EC':
                return $this->convertEcKeyToPem($jwk);
            default:
                throw new InvalidArgumentException('Unsupported key type: ' . $jwk['kty']);
        }
    }

    /**
     * Convert RSA JWK to PEM format
     *
     * @param array $jwk The RSA JWK
     * @return string The PEM formatted key
     */
    private function convertRsaKeyToPem(array $jwk): string
    {
        if (!isset($jwk['n']) || !isset($jwk['e'])) {
            throw new InvalidArgumentException('Missing required RSA parameters (n, e)');
        }

        $modulus = $this->base64UrlDecode($jwk['n']);
        $exponent = $this->base64UrlDecode($jwk['e']);

        // Create ASN.1 DER structure for RSA public key
        $modulusHex = bin2hex($modulus);
        $exponentHex = bin2hex($exponent);
        
        // This is a simplified conversion - for production use, consider using a proper ASN.1 library
        $der = $this->createRsaDerStructure($modulusHex, $exponentHex);
        
        return "-----BEGIN PUBLIC KEY-----\n" . 
               chunk_split(base64_encode(hex2bin($der)), 64) . 
               "-----END PUBLIC KEY-----\n";
    }

    /**
     * Convert EC JWK to PEM format (placeholder)
     *
     * @param array $jwk The EC JWK
     * @return string The PEM formatted key
     * @throws InvalidArgumentException Always, as EC is not yet implemented
     */
    private function convertEcKeyToPem(array $jwk): string
    {
        throw new InvalidArgumentException('EC key conversion not yet implemented');
    }

    /**
     * Create RSA DER structure (simplified implementation)
     */
    private function createRsaDerStructure(string $modulusHex, string $exponentHex): string
    {
        // This is a very basic implementation - for production, use proper ASN.1 encoding
        $modulus = $this->createDerInteger($modulusHex);
        $exponent = $this->createDerInteger($exponentHex);
        $sequence = $modulus . $exponent;
        $sequenceLength = strlen($sequence) / 2;
        
        return '30' . $this->createDerLength($sequenceLength) . $sequence;
    }

    /**
     * Create DER integer encoding
     */
    private function createDerInteger(string $hex): string
    {
        // Add padding if first bit is 1 (to keep it positive)
        if (hexdec(substr($hex, 0, 2)) >= 128) {
            $hex = '00' . $hex;
        }
        
        $length = strlen($hex) / 2;
        return '02' . $this->createDerLength($length) . $hex;
    }

    /**
     * Create DER length encoding
     */
    private function createDerLength(int $length): string
    {
        if ($length < 128) {
            return sprintf('%02x', $length);
        }
        
        $lengthHex = dechex($length);
        if (strlen($lengthHex) % 2) {
            $lengthHex = '0' . $lengthHex;
        }
        
        $lengthOfLength = strlen($lengthHex) / 2;
        return sprintf('%02x', 128 + $lengthOfLength) . $lengthHex;
    }

    /**
     * Base64 URL decode
     */
    private function base64UrlDecode(string $data): string
    {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $data .= str_repeat('=', 4 - $remainder);
        }
        
        return base64_decode(strtr($data, '-_', '+/'));
    }

    private function getCacheKey(): string
    {
        return 'authlib_jwks_' . md5($this->jwksUri);
    }
}