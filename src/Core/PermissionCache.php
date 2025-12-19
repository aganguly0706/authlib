<?php

declare(strict_types=1);

namespace authlib\Auth\Core;

/**
 * Permission cache for storing authorization decisions
 * Respects token TTL limits and provides observability metrics
 */
final class PermissionCache
{
    private array $cache = [];
    private int $defaultTtl;
    private int $maxTtl;
    private array $metrics = [
        'hits' => 0,
        'misses' => 0,
        'sets' => 0,
        'deletes' => 0,
        'denials' => 0
    ];

    public function __construct(int $defaultTtl = 600, int $maxTtl = 3600)
    {
        $this->defaultTtl = $defaultTtl;
        $this->maxTtl = $maxTtl; // Never cache longer than max token age
    }

    /**
     * Check if cache has a key
     *
     * @param string $key Cache key (will be sanitized)
     * @return bool True if key exists and not expired
     */
    public function has(string $key): bool
    {
        $key = $this->sanitizeKey($key);
        
        if (!isset($this->cache[$key])) {
            $this->metrics['misses']++;
            return false;
        }

        $entry = $this->cache[$key];
        if ($entry['expires'] < time()) {
            unset($this->cache[$key]);
            $this->metrics['misses']++;
            return false;
        }

        $this->metrics['hits']++;
        return true;
    }

    /**
     * Get value from cache
     *
     * @param string $key Cache key (will be sanitized)
     * @return mixed Cached value or null if not found/expired
     */
    public function get(string $key): mixed
    {
        $key = $this->sanitizeKey($key);
        
        if (!$this->has($key)) {
            return null;
        }

        return $this->cache[$key]['value'];
    }

    /**
     * Set value in cache with TTL enforcement
     *
     * @param string $key Cache key (will be sanitized)
     * @param mixed $value Value to cache
     * @param int|null $ttl Time to live in seconds (limited by maxTtl)
     * @return void
     */
    public function set(string $key, mixed $value, ?int $ttl = null): void
    {
        $key = $this->sanitizeKey($key);
        $ttl = $ttl ?? $this->defaultTtl;
        
        // Enforce maximum TTL - never cache longer than token TTL
        $ttl = min($ttl, $this->maxTtl);
        
        $this->cache[$key] = [
            'value' => $value,
            'expires' => time() + $ttl,
            'created' => time()
        ];
        
        $this->metrics['sets']++;
        
        // Track denial rates for observability
        if ($value === false) {
            $this->metrics['denials']++;
        }
    }

    /**
     * Delete key from cache
     *
     * @param string $key Cache key
     * @return void
     */
    public function delete(string $key): void
    {
        $key = $this->sanitizeKey($key);
        unset($this->cache[$key]);
        $this->metrics['deletes']++;
    }

    /**
     * Delete key from cache by prefix (for invalidation)
     *
     * @param string $prefix Key prefix to match
     * @return int Number of keys deleted
     */
    public function deleteByPrefix(string $prefix): int
    {
        $prefix = $this->sanitizeKey($prefix);
        $deleted = 0;
        
        foreach (array_keys($this->cache) as $key) {
            if (str_starts_with($key, $prefix)) {
                unset($this->cache[$key]);
                $deleted++;
            }
        }
        
        $this->metrics['deletes'] += $deleted;
        return $deleted;
    }

    /**
     * Clear all cache entries
     *
     * @return void
     */
    public function clear(): void
    {
        $this->cache = [];
    }

    /**
     * Get cache statistics
     *
     * @return array Cache statistics
     */
    public function getStats(): array
    {
        $total = count($this->cache);
        $expired = 0;
        $now = time();

        foreach ($this->cache as $entry) {
            if ($entry['expires'] < $now) {
                $expired++;
            }
        }

        return [
            'total_entries' => $total,
            'active_entries' => $total - $expired,
            'expired_entries' => $expired,
        ];
    }

    /**
     * Get observability metrics for monitoring
     *
     * @return array Metrics including hit rates and denial rates
     */
    public function getMetrics(): array
    {
        $totalRequests = $this->metrics['hits'] + $this->metrics['misses'];
        $hitRate = $totalRequests > 0 ? $this->metrics['hits'] / $totalRequests : 0;
        $denialRate = $this->metrics['sets'] > 0 ? $this->metrics['denials'] / $this->metrics['sets'] : 0;
        
        return [
            'hits' => $this->metrics['hits'],
            'misses' => $this->metrics['misses'],
            'sets' => $this->metrics['sets'],
            'deletes' => $this->metrics['deletes'],
            'denials' => $this->metrics['denials'],
            'hit_rate' => round($hitRate * 100, 2),
            'denial_rate' => round($denialRate * 100, 2),
            'total_entries' => count($this->cache),
            'memory_usage' => $this->estimateMemoryUsage()
        ];
    }

    /**
     * Reset metrics (useful for monitoring intervals)
     */
    public function resetMetrics(): void
    {
        $this->metrics = [
            'hits' => 0,
            'misses' => 0,
            'sets' => 0,
            'deletes' => 0,
            'denials' => 0
        ];
    }

    /**
     * Clean expired entries
     *
     * @return int Number of entries cleaned
     */
    public function cleanup(): int
    {
        $cleaned = 0;
        $now = time();

        foreach ($this->cache as $key => $entry) {
            if ($entry['expires'] < $now) {
                unset($this->cache[$key]);
                $cleaned++;
            }
        }

        return $cleaned;
    }

    /**
     * Generate cache key with context hash
     *
     * @param string $userId User identifier
     * @param string $permission Permission being checked
     * @param array $context Context for the permission check
     * @return string Sanitized cache key
     */
    public function generateKey(string $userId, string $permission, array $context = []): string
    {
        $contextHash = $this->generateContextHash($context);
        return sprintf(
            'perm:%s:%s:%s',
            $this->sanitizeUserId($userId),
            $this->sanitizePermission($permission),
            $contextHash
        );
    }

    /**
     * Sanitize cache key to prevent injection
     */
    private function sanitizeKey(string $key): string
    {
        // Only allow alphanumeric, colons, underscores, and hyphens
        $sanitized = preg_replace('/[^A-Za-z0-9:_-]/', '', $key);
        return substr($sanitized, 0, 200); // Limit key length
    }

    /**
     * Sanitize user ID for cache key
     */
    private function sanitizeUserId(string $userId): string
    {
        return preg_replace('/[^A-Za-z0-9@._-]/', '', $userId);
    }

    /**
     * Sanitize permission for cache key
     */
    private function sanitizePermission(string $permission): string
    {
        return preg_replace('/[^A-Za-z0-9._-]/', '', $permission);
    }

    /**
     * Generate context hash for consistent cache keys
     */
    private function generateContextHash(array $context): string
    {
        // Sort context for consistent hashing
        ksort($context);
        
        // Remove volatile data that shouldn't affect caching
        $filteredContext = array_filter($context, function($key) {
            return !in_array($key, ['request_id', 'timestamp', 'cache_used'], true);
        }, ARRAY_FILTER_USE_KEY);
        
        return substr(hash('sha256', serialize($filteredContext)), 0, 16);
    }

    /**
     * Estimate memory usage of cache
     */
    private function estimateMemoryUsage(): int
    {
        return strlen(serialize($this->cache));
    }
}