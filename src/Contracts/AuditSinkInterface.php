<?php

declare(strict_types=1);

namespace authlib\Auth\Contracts;

/**
 * Interface for audit logging
 */
interface AuditSinkInterface
{
    /**
     * Log an authorization event
     *
     * @param string $event The event type (e.g., 'permission_check', 'role_check', 'authorization')
     * @param string $userId The user ID involved in the event
     * @param array<string, mixed> $data Additional event data
     * @return void
     */
    public function logAuthorizationEvent(string $event, string $userId, array $data = []): void;

    /**
     * Log a permission granted event
     *
     * @param string $userId The user ID
     * @param string $permission The permission that was granted
     * @param array<string, mixed> $context Additional context
     * @return void
     */
    public function logPermissionGranted(string $userId, string $permission, array $context = []): void;

    /**
     * Log a permission denied event
     *
     * @param string $userId The user ID
     * @param string $permission The permission that was denied
     * @param array<string, mixed> $context Additional context
     * @return void
     */
    public function logPermissionDenied(string $userId, string $permission, array $context = []): void;

    /**
     * Log a token validation event
     *
     * @param string $event The event type (e.g., 'token_valid', 'token_invalid', 'token_expired')
     * @param string $token The token (should be hashed/masked for security)
     * @param array<string, mixed> $data Additional event data
     * @return void
     */
    public function logTokenEvent(string $event, string $token, array $data = []): void;

    /**
     * Log a security event
     *
     * @param string $event The event type
     * @param array<string, mixed> $data Event data
     * @return void
     */
    public function logSecurityEvent(string $event, array $data = []): void;

    /**
     * Log an authorization decision
     *
     * @param string $userId The user identifier
     * @param string $permission The permission that was checked
     * @param bool $granted Whether the permission was granted
     * @param array<string, mixed> $context Additional context data
     * @return void
     */
    public function logDecision(string $userId, string $permission, bool $granted, array $context = []): void;
}