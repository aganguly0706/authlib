<?php

declare(strict_types=1);

namespace authlib\Auth\Contracts;

use stdClass;

/**
 * Interface for token validation services
 */
interface TokenValidatorInterface
{
    /**
     * Validate a token and return its payload
     *
     * @param string $token The token to validate
     * @return stdClass The validated token payload
     * @throws \Exception When token validation fails
     */
    public function validate(string $token): stdClass;

    /**
     * Check if a token is valid without returning payload
     *
     * @param string $token The token to check
     * @return bool True if token is valid, false otherwise
     */
    public function isValid(string $token): bool;

    /**
     * Get the issuer this validator accepts
     *
     * @return string|null The accepted issuer
     */
    public function getAcceptedIssuer(): ?string;

    /**
     * Get the audience this validator accepts
     *
     * @return string|null The accepted audience
     */
    public function getAcceptedAudience(): ?string;

    /**
     * Validate and decode a JWT token
     *
     * @param string $jwt The JWT token to validate
     * @return array Decoded JWT claims
     * @throws \Exception When token validation fails
     */
    public function validateAndDecode(string $jwt): array;
}