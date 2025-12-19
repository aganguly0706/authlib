<?php

declare(strict_types=1);

namespace authlib\Auth\Tests;

use PHPUnit\Framework\TestCase;
use authlib\Auth\Core\PermissionCache;

/**
 * Test suite for PermissionCache
 */
class PermissionCacheTest extends TestCase
{
    private PermissionCache $cache;

    protected function setUp(): void
    {
        $this->cache = new PermissionCache(600); // 10 minute default TTL
    }

    public function testHasReturnsFalseForNonExistentKey(): void
    {
        $this->assertFalse($this->cache->has('nonexistent'));
    }

    public function testSetAndGetValue(): void
    {
        $key = 'test_key';
        $value = 'test_value';

        $this->cache->set($key, $value);
        $this->assertTrue($this->cache->has($key));
        $this->assertEquals($value, $this->cache->get($key));
    }

    public function testGetReturnsNullForNonExistentKey(): void
    {
        $this->assertNull($this->cache->get('nonexistent'));
    }

    public function testSetWithCustomTtl(): void
    {
        $key = 'test_key';
        $value = 'test_value';

        $this->cache->set($key, $value, 1); // 1 second TTL
        $this->assertTrue($this->cache->has($key));

        sleep(2); // Wait for expiry
        $this->assertFalse($this->cache->has($key));
    }

    public function testDelete(): void
    {
        $key = 'test_key';
        $value = 'test_value';

        $this->cache->set($key, $value);
        $this->assertTrue($this->cache->has($key));

        $this->cache->delete($key);
        $this->assertFalse($this->cache->has($key));
    }

    public function testClear(): void
    {
        $this->cache->set('key1', 'value1');
        $this->cache->set('key2', 'value2');

        $this->assertTrue($this->cache->has('key1'));
        $this->assertTrue($this->cache->has('key2'));

        $this->cache->clear();
        $this->assertFalse($this->cache->has('key1'));
        $this->assertFalse($this->cache->has('key2'));
    }

    public function testGetStatsReturnsCorrectCounts(): void
    {
        $this->cache->set('key1', 'value1');
        $this->cache->set('key2', 'value2', 1); // Will expire quickly

        $stats = $this->cache->getStats();
        $this->assertEquals(2, $stats['total_entries']);

        sleep(2); // Let one expire
        $stats = $this->cache->getStats();
        $this->assertEquals(2, $stats['total_entries']);
        $this->assertEquals(1, $stats['active_entries']);
        $this->assertEquals(1, $stats['expired_entries']);
    }

    public function testCleanupRemovesExpiredEntries(): void
    {
        $this->cache->set('key1', 'value1');
        $this->cache->set('key2', 'value2', 1); // Will expire quickly

        sleep(2); // Let one expire
        $cleaned = $this->cache->cleanup();
        
        $this->assertEquals(1, $cleaned);
        $this->assertTrue($this->cache->has('key1'));
        $this->assertFalse($this->cache->has('key2'));
    }

    public function testSetOverwritesExistingKey(): void
    {
        $key = 'test_key';
        
        $this->cache->set($key, 'value1');
        $this->assertEquals('value1', $this->cache->get($key));

        $this->cache->set($key, 'value2');
        $this->assertEquals('value2', $this->cache->get($key));
    }

    public function testSetWithBooleanValues(): void
    {
        $this->cache->set('true_key', true);
        $this->cache->set('false_key', false);

        $this->assertTrue($this->cache->get('true_key'));
        $this->assertFalse($this->cache->get('false_key'));
    }

    public function testSetWithArrayValues(): void
    {
        $array = ['item1', 'item2', 'item3'];
        $this->cache->set('array_key', $array);

        $this->assertEquals($array, $this->cache->get('array_key'));
    }
}