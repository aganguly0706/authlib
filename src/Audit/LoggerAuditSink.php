<?php

declare(strict_types=1);

namespace authlib\Auth\Audit;

use authlib\Auth\Contracts\AuditSinkInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;

/**
 * Comprehensive audit sink with policy version tracking
 * Logs all authorization decisions with bindings hash for compliance
 */
final class LoggerAuditSink implements AuditSinkInterface
{
    private LoggerInterface $logger;
    private string $bindingsHash = '';

    public function __construct(LoggerInterface $logger)
    {
        $this->logger = $logger;
        $this->updateBindingsHash();
    }

    /**
     * Log a permission grant with full context and policy version
     */
    public function logPermissionGranted(string $userId, string $permission, array $context = []): void
    {
        $this->logDecision($userId, $permission, true, $context);
    }

    /**
     * Log a permission denial with full context and policy version
     */
    public function logPermissionDenied(string $userId, string $permission, array $context = []): void
    {
        $this->logDecision($userId, $permission, false, $context);
    }

    /**
     * Log an authorization decision with comprehensive audit data
     */
    public function logDecision(string $userId, string $permission, bool $granted, array $context = []): void
    {
        $level = $granted ? LogLevel::INFO : LogLevel::WARNING;
        
        $auditData = [
            'event_type' => 'authorization_decision',
            'timestamp' => gmdate('c'),
            'user_id' => $this->sanitizeUserId($userId),
            'permission' => $this->sanitizePermission($permission),
            'result' => $granted ? 'granted' : 'denied',
            'policy_version' => $this->bindingsHash,
            'context' => $this->sanitizeContext($context),
            'request_id' => $context['request_id'] ?? $this->generateRequestId(),
            'session_id' => $context['session_id'] ?? null,
            'ip_address' => $context['ip_address'] ?? null,
            'user_agent' => $context['user_agent'] ?? null,
            'cache_used' => $context['cache_used'] ?? false,
            'denial_reason' => $granted ? null : ($context['reason'] ?? 'Insufficient permissions')
        ];

        $this->logger->log($level, 'Authorization decision', $auditData);
    }

    /**
     * Log general authorization events with policy tracking
     */
    public function logAuthorizationEvent(string $eventType, string $userId, array $context = []): void
    {
        $level = $this->getLogLevelForEvent($eventType);
        
        $auditData = [
            'event_type' => $eventType,
            'timestamp' => gmdate('c'),
            'user_id' => $this->sanitizeUserId($userId),
            'policy_version' => $this->bindingsHash,
            'context' => $this->sanitizeContext($context),
            'request_id' => $context['request_id'] ?? $this->generateRequestId()
        ];

        $this->logger->log($level, "Authorization event: {$eventType}", $auditData);
    }

    /**
     * Log token validation events with security context
     */
    public function logTokenEvent(string $eventType, string $maskedToken, array $context = []): void
    {
        $level = match ($eventType) {
            'token_invalid', 'token_expired', 'token_malformed' => LogLevel::WARNING,
            'token_valid' => LogLevel::INFO,
            default => LogLevel::NOTICE,
        };

        $auditData = [
            'event_type' => $eventType,
            'timestamp' => gmdate('c'),
            'masked_token' => $maskedToken,
            'context' => $this->sanitizeContext($context),
            'request_id' => $context['request_id'] ?? $this->generateRequestId(),
            'ip_address' => $context['ip_address'] ?? null,
            'user_agent' => $context['user_agent'] ?? null
        ];

        $this->logger->log($level, "Token event: {$eventType}", $auditData);
    }

    /**
     * Log security events with high visibility
     */
    public function logSecurityEvent(string $eventType, array $context = []): void
    {
        $level = match ($eventType) {
            'brute_force_attempt', 'suspicious_activity', 'token_tampering' => LogLevel::ERROR,
            'rate_limit_exceeded', 'multiple_failed_attempts' => LogLevel::WARNING,
            'login_success', 'logout' => LogLevel::INFO,
            default => LogLevel::WARNING,
        };

        $auditData = [
            'event_type' => 'security_event',
            'security_event_type' => $eventType,
            'timestamp' => gmdate('c'),
            'policy_version' => $this->bindingsHash,
            'context' => $this->sanitizeContext($context),
            'request_id' => $context['request_id'] ?? $this->generateRequestId(),
            'ip_address' => $context['ip_address'] ?? null,
            'severity' => $level
        ];

        $this->logger->log($level, "Security event: {$eventType}", $auditData);
    }

    /**
     * Update the bindings hash to track policy changes
     */
    public function updateBindingsHash(?string $hash = null): void
    {
        if ($hash !== null) {
            $this->bindingsHash = $hash;
        } else {
            // Generate hash based on current timestamp for versioning
            $this->bindingsHash = hash('sha256', time() . '_policy_version');
        }
    }

    /**
     * Get current policy version hash
     */
    public function getPolicyVersion(): string
    {
        return $this->bindingsHash;
    }

    /**
     * Sanitize user ID for logging (prevent injection)
     */
    private function sanitizeUserId(string $userId): string
    {
        // Remove any control characters and limit length
        $sanitized = preg_replace('/[\x00-\x1F\x7F]/', '', $userId);
        return substr($sanitized, 0, 255);
    }

    /**
     * Sanitize permission string for logging
     */
    private function sanitizePermission(string $permission): string
    {
        // Only allow alphanumeric, dots, underscores, and hyphens
        $sanitized = preg_replace('/[^A-Za-z0-9._-]/', '', $permission);
        return substr($sanitized, 0, 100);
    }

    /**
     * Sanitize context data to prevent log injection
     */
    private function sanitizeContext(array $context): array
    {
        $sanitized = [];
        
        foreach ($context as $key => $value) {
            $cleanKey = preg_replace('/[^A-Za-z0-9_]/', '', (string)$key);
            
            if (is_string($value)) {
                // Remove control characters and limit length
                $sanitized[$cleanKey] = substr(preg_replace('/[\x00-\x1F\x7F]/', '', $value), 0, 500);
            } elseif (is_array($value)) {
                // Recursively sanitize arrays (limited depth)
                $sanitized[$cleanKey] = $this->sanitizeArrayValue($value, 2);
            } elseif (is_scalar($value)) {
                $sanitized[$cleanKey] = $value;
            }
        }
        
        return $sanitized;
    }

    /**
     * Sanitize array values with depth limit
     */
    private function sanitizeArrayValue(array $array, int $maxDepth): array
    {
        if ($maxDepth <= 0) {
            return ['_truncated' => 'max_depth_reached'];
        }

        $sanitized = [];
        $count = 0;
        
        foreach ($array as $key => $value) {
            if ($count++ > 20) { // Limit array size
                $sanitized['_truncated'] = 'array_too_large';
                break;
            }

            $cleanKey = is_string($key) ? preg_replace('/[^A-Za-z0-9_]/', '', $key) : $key;
            
            if (is_string($value)) {
                $sanitized[$cleanKey] = substr(preg_replace('/[\x00-\x1F\x7F]/', '', $value), 0, 200);
            } elseif (is_array($value)) {
                $sanitized[$cleanKey] = $this->sanitizeArrayValue($value, $maxDepth - 1);
            } elseif (is_scalar($value)) {
                $sanitized[$cleanKey] = $value;
            }
        }
        
        return $sanitized;
    }

    /**
     * Generate a unique request ID for tracking
     */
    private function generateRequestId(): string
    {
        return uniqid('req_', true);
    }

    /**
     * Get appropriate log level for event type
     */
    private function getLogLevelForEvent(string $eventType): string
    {
        return match ($eventType) {
            'role_check', 'permission_check' => LogLevel::INFO,
            'access_denied', 'insufficient_privileges' => LogLevel::WARNING,
            'policy_violation', 'security_concern' => LogLevel::ERROR,
            default => LogLevel::NOTICE,
        };
    }
}