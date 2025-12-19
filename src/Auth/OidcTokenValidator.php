<?php

declare(strict_types=1);

namespace authlib\Auth\Auth;

use authlib\Auth\Contracts\TokenValidatorInterface;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\SignatureInvalidException;
use InvalidArgumentException;
use stdClass;
use Exception;
use Psr\Cache\CacheItemPoolInterface;

/**
 * OIDC token validator with comprehensive security validation
 * Implements clock skew handling, strict validation, and key rotation support
 */
final class OidcTokenValidator implements TokenValidatorInterface
{
    private array $jwks = [];
    private ?CacheItemPoolInterface $cache;
    private int $cacheTtl;
    private int $clockSkewTolerance = 60; // ±60 seconds for clock skew
    private int $maxTokenAge = 3600; // Maximum token age in seconds

    public function __construct(
        private readonly string $issuer,
        private readonly string $audience,
        private readonly ?string $jwksUri = null,
        private readonly ?string $jwksFilePath = null,
        ?array $staticJwks = null,
        ?CacheItemPoolInterface $cache = null,
        int $cacheTtl = 3600,
        int $clockSkewTolerance = 60,
        int $maxTokenAge = 3600
    ) {
        $this->cache = $cache;
        $this->cacheTtl = $cacheTtl;
        $this->clockSkewTolerance = max(0, min(300, $clockSkewTolerance)); // Cap at 5 minutes
        $this->maxTokenAge = $maxTokenAge;

        if ($staticJwks) {
            $this->jwks = $staticJwks;
        } elseif ($jwksFilePath && file_exists($jwksFilePath)) {
            $this->loadJwksFromFile($jwksFilePath);
        } elseif ($jwksUri) {
            $this->loadJwksFromUri($jwksUri);
        } else {
            throw new InvalidArgumentException('Must provide either JWKS URI, file path, or static JWKS array');
        }
    }

    public function validateAndDecode(string $jwt): array
    {
        $claims = $this->validate($jwt);
        return json_decode(json_encode($claims), true);
    }

    public function validate(string $token): stdClass
    {
        try {
            // Basic token format validation
            $this->validateTokenFormat($token);
            
            $header = $this->getHeader($token);
            
            // Validate algorithm is allowed
            $this->validateAlgorithm($header);
            
            if (!isset($header->kid)) {
                throw new InvalidArgumentException('Token header missing key ID (kid)');
            }

            $key = $this->getKey($header->kid);
            
            if (!$key) {
                throw new InvalidArgumentException('Unknown key id (kid): ' . $header->kid);
            }

            $algorithm = $header->alg ?? 'RS256';
            $decoded = JWT::decode($token, new Key($key, $algorithm));

            // Comprehensive claims validation with clock skew
            $this->validateClaims($decoded);

            return $decoded;
        } catch (ExpiredException $e) {
            throw new Exception('Token has expired: ' . $e->getMessage(), 0, $e);
        } catch (SignatureInvalidException $e) {
            throw new Exception('Token signature is invalid: ' . $e->getMessage(), 0, $e);
        } catch (Exception $e) {
            throw new Exception('Token validation failed: ' . $e->getMessage(), 0, $e);
        }
    }

    public function isValid(string $token): bool
    {
        try {
            $this->validate($token);
            return true;
        } catch (Exception) {
            return false;
        }
    }

    public function getAcceptedIssuer(): ?string
    {
        return $this->issuer;
    }

    public function getAcceptedAudience(): ?string
    {
        return $this->audience;
    }

    private function getHeader(string $token): stdClass
    {
        $parts = explode('.', $token);
        
        if (count($parts) !== 3) {
            throw new InvalidArgumentException('Invalid JWT format');
        }

        $header = json_decode(JWT::urlsafeB64Decode($parts[0]));
        
        if (!$header) {
            throw new InvalidArgumentException('Invalid JWT header');
        }

        return $header;
    }

    private function getKey(string $kid): ?string
    {
        // Try to get from static JWKS first
        if (isset($this->jwks[$kid])) {
            return $this->jwks[$kid];
        }

        // If we have a JWKS URI, try to refresh the keys
        if ($this->jwksUri) {
            $this->loadJwksFromUri($this->jwksUri);
            return $this->jwks[$kid] ?? null;
        }

        return null;
    }

    private function loadJwksFromFile(string $filePath): void
    {
        $jwksData = file_get_contents($filePath);
        if ($jwksData === false) {
            throw new InvalidArgumentException('Unable to read JWKS file: ' . $filePath);
        }

        $jwks = json_decode($jwksData, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new InvalidArgumentException('Invalid JSON in JWKS file: ' . json_last_error_msg());
        }

        $this->parseJwks($jwks);
    }

    private function loadJwksFromUri(string $uri): void
    {
        $cacheKey = 'jwks_' . md5($uri);
        
        // Try cache first
        if ($this->cache) {
            $item = $this->cache->getItem($cacheKey);
            if ($item->isHit()) {
                $this->jwks = array_merge($this->jwks, $item->get());
                return;
            }
        }

        // Fetch from URI
        $context = stream_context_create([
            'http' => [
                'timeout' => 30,
                'user_agent' => 'AuthLib OIDC Validator/1.0'
            ]
        ]);

        $jwksData = file_get_contents($uri, false, $context);
        if ($jwksData === false) {
            throw new Exception('Unable to fetch JWKS from URI: ' . $uri);
        }

        $jwks = json_decode($jwksData, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception('Invalid JSON in JWKS response: ' . json_last_error_msg());
        }

        $parsedKeys = $this->parseJwks($jwks);

        // Cache the parsed keys
        if ($this->cache && !empty($parsedKeys)) {
            $item->set($parsedKeys)->expiresAfter($this->cacheTtl);
            $this->cache->save($item);
        }
    }

    private function parseJwks(array $jwks): array
    {
        $keys = [];
        
        if (!isset($jwks['keys']) || !is_array($jwks['keys'])) {
            throw new InvalidArgumentException('Invalid JWKS format: missing keys array');
        }

        foreach ($jwks['keys'] as $key) {
            if (!isset($key['kid'])) {
                continue; // Skip keys without kid
            }

            $kid = $key['kid'];
            
            if (isset($key['x5c']) && !empty($key['x5c'])) {
                // X.509 certificate chain
                $cert = "-----BEGIN CERTIFICATE-----\n" . 
                       chunk_split($key['x5c'][0], 64, "\n") . 
                       "-----END CERTIFICATE-----\n";
                $keys[$kid] = $cert;
            } elseif (isset($key['n']) && isset($key['e']) && $key['kty'] === 'RSA') {
                // RSA public key from modulus and exponent
                $keys[$kid] = $this->createRsaKey($key);
            } elseif (isset($key['x']) && isset($key['y']) && $key['kty'] === 'EC') {
                // EC public key (for future support)
                continue;
            }
        }

        $this->jwks = array_merge($this->jwks, $keys);
        return $keys;
    }

    private function createRsaKey(array $key): string
    {
        // Convert JWK RSA to PEM format
        $n = JWT::urlsafeB64Decode($key['n']);
        $e = JWT::urlsafeB64Decode($key['e']);
        
        // This is a simplified conversion - in production you might want to use
        // a more robust library like web-token/jwt-framework
        $modulus = base64_encode($n);
        $exponent = base64_encode($e);
        
        // For now, we'll store the raw components and let firebase/jwt handle the conversion
        // This requires the key to be in the right format for firebase/jwt
        throw new Exception('RSA JWK to PEM conversion not fully implemented. Use X.509 certificates in JWKS.');
    }

    /**
     * Validate token format before processing
     */
    private function validateTokenFormat(string $token): void
    {
        if (empty($token)) {
            throw new InvalidArgumentException('Token cannot be empty');
        }

        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new InvalidArgumentException('Invalid JWT format: expected 3 parts');
        }

        // Validate each part is base64url encoded
        foreach ($parts as $i => $part) {
            if (empty($part)) {
                throw new InvalidArgumentException("JWT part {$i} cannot be empty");
            }
            
            // Check for valid base64url characters
            if (!preg_match('/^[A-Za-z0-9_-]*$/', $part)) {
                throw new InvalidArgumentException("JWT part {$i} contains invalid characters");
            }
        }
    }

    /**
     * Validate JWT algorithm is secure and allowed
     */
    private function validateAlgorithm(stdClass $header): void
    {
        if (!isset($header->alg)) {
            throw new InvalidArgumentException('Token header missing algorithm');
        }

        // Only allow secure algorithms
        $allowedAlgorithms = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512'];
        
        if (!in_array($header->alg, $allowedAlgorithms, true)) {
            throw new InvalidArgumentException('Unsupported or insecure algorithm: ' . $header->alg);
        }

        // Explicitly deny 'none' algorithm
        if ($header->alg === 'none') {
            throw new InvalidArgumentException('Algorithm "none" is not allowed');
        }
    }

    /**
     * Enhanced claims validation with clock skew tolerance
     */
    private function validateClaims(stdClass $payload): void
    {
        $now = time();

        // Validate required claims exist
        $this->validateRequiredClaims($payload);

        // Validate expiration time with clock skew
        if (isset($payload->exp)) {
            if (!is_numeric($payload->exp)) {
                throw new InvalidArgumentException('exp claim must be numeric');
            }
            
            if ($payload->exp < ($now - $this->clockSkewTolerance)) {
                throw new ExpiredException('Token has expired');
            }
        }

        // Validate not before time with clock skew
        if (isset($payload->nbf)) {
            if (!is_numeric($payload->nbf)) {
                throw new InvalidArgumentException('nbf claim must be numeric');
            }
            
            if ($payload->nbf > ($now + $this->clockSkewTolerance)) {
                throw new Exception('Token not yet valid (nbf)');
            }
        }

        // Validate issued at time
        if (isset($payload->iat)) {
            if (!is_numeric($payload->iat)) {
                throw new InvalidArgumentException('iat claim must be numeric');
            }
            
            // Token cannot be issued in the future (with clock skew tolerance)
            if ($payload->iat > ($now + $this->clockSkewTolerance)) {
                throw new InvalidArgumentException('Token issued in the future');
            }
            
            // Token cannot be too old
            if (($now - $payload->iat) > $this->maxTokenAge) {
                throw new InvalidArgumentException('Token is too old');
            }
        }

        // Validate issuer exactly
        if (isset($payload->iss)) {
            if ($payload->iss !== $this->issuer) {
                throw new InvalidArgumentException('Invalid issuer: expected ' . $this->issuer . ', got ' . $payload->iss);
            }
        }

        // Validate audience
        if (isset($payload->aud)) {
            $audiences = is_array($payload->aud) ? $payload->aud : [$payload->aud];
            if (!in_array($this->audience, $audiences, true)) {
                throw new InvalidArgumentException('Invalid audience: expected ' . $this->audience);
            }
        }

        // Validate JWT ID if present (for blacklist checking)
        if (isset($payload->jti)) {
            if (!is_string($payload->jti) || empty($payload->jti)) {
                throw new InvalidArgumentException('jti claim must be a non-empty string');
            }
        }

        // Validate subject if present
        if (isset($payload->sub)) {
            if (!is_string($payload->sub) || empty($payload->sub)) {
                throw new InvalidArgumentException('sub claim must be a non-empty string');
            }
        }
    }

    /**
     * Validate required claims are present
     */
    private function validateRequiredClaims(stdClass $payload): void
    {
        $requiredClaims = ['iss', 'aud', 'exp', 'sub'];
        
        foreach ($requiredClaims as $claim) {
            if (!isset($payload->$claim)) {
                throw new InvalidArgumentException("Missing required claim: {$claim}");
            }
        }
    }

    /**
     * Clear the JWKS cache
     */
    public function clearCache(): bool
    {
        if (!$this->cache || !$this->jwksUri) {
            return false;
        }

        $cacheKey = 'jwks_' . md5($this->jwksUri);
        return $this->cache->deleteItem($cacheKey);
    }

    /**
     * Get current JWKS keys
     */
    public function getJwks(): array
    {
        return $this->jwks;
    }
}