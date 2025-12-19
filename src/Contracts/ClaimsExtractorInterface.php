<?php

declare(strict_types=1);

namespace authlib\Auth\Contracts;

use stdClass;

/**
 * Interface for extracting claims from validated tokens
 */
interface ClaimsExtractorInterface
{
    /**
     * Extract claims from a token payload
     *
     * @param stdClass $payload The validated token payload
     * @return array<string, mixed> Extracted claims
     */
    public function extractClaims(stdClass $payload): array;

    /**
     * Get user ID from token payload
     *
     * @param stdClass $payload The validated token payload
     * @return string|null The user ID
     */
    public function getUserId(stdClass $payload): ?string;

    /**
     * Get user roles from token payload
     *
     * @param stdClass $payload The validated token payload
     * @return array<string> User roles
     */
    public function getRoles(stdClass $payload): array;

    /**
     * Get user permissions from token payload
     *
     * @param stdClass $payload The validated token payload
     * @return array<string> User permissions
     */
    public function getPermissions(stdClass $payload): array;

    /**
     * Get custom claims from token payload
     *
     * @param stdClass $payload The validated token payload
     * @return array<string, mixed> Custom claims
     */
    public function getCustomClaims(stdClass $payload): array;

    /**
     * Extract normalized group IDs from token claims
     *
     * @param array $claims The validated token claims
     * @return string[] Normalized group IDs (or roles)
     */
    public function extractGroups(array $claims): array;

    /**
     * Extract user ID from token claims
     *
     * @param array $claims The validated token claims
     * @return string User ID (sub or preferred_username)
     * @throws \InvalidArgumentException When user ID cannot be extracted
     */
    public function extractUserId(array $claims): string;
}