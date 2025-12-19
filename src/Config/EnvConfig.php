<?php

declare(strict_types=1);

namespace authlib\Auth\Config;

use Dotenv\Dotenv;
use InvalidArgumentException;

/**
 * Environment-based configuration for AuthLib
 */
class EnvConfig
{
    private array $config = [];

    public function __construct(?string $envPath = null)
    {
        // Optionally load .env file if path is provided and file exists
        if ($envPath && file_exists($envPath)) {
            $dotenv = Dotenv::createImmutable(dirname($envPath), basename($envPath));
            $dotenv->load();
        } elseif ($envPath === null && file_exists('.env')) {
            // Auto-load .env from current directory if no path specified
            $dotenv = Dotenv::createImmutable('.');
            $dotenv->load();
        }

        $this->loadConfiguration();
    }

    /**
     * Load .env file from specified directory
     *
     * @param string $directory Directory containing .env file
     * @param string $filename Optional filename (defaults to '.env')
     * @return void
     */
    public static function loadEnv(string $directory = '.', string $filename = '.env'): void
    {
        if (file_exists($directory . DIRECTORY_SEPARATOR . $filename)) {
            $dotenv = Dotenv::createImmutable($directory, $filename);
            $dotenv->load();
        }
    }

    private function loadConfiguration(): void
    {
        $this->config = [
            'jwks_uri' => $this->getEnv('AUTH_JWKS_URI'),
            'issuer' => $this->getEnv('AUTH_ISSUER'),
            'audience' => $this->getEnv('AUTH_AUDIENCE'),
            'cache_ttl' => (int) $this->getEnv('AUTH_CACHE_TTL', '3600'),
            'db' => [
                'host' => $this->getEnv('DB_HOST', 'localhost'),
                'port' => (int) $this->getEnv('DB_PORT', '3306'),
                'database' => $this->getEnv('DB_DATABASE'),
                'username' => $this->getEnv('DB_USERNAME'),
                'password' => $this->getEnv('DB_PASSWORD'),
                'charset' => $this->getEnv('DB_CHARSET', 'utf8mb4'),
            ],
            'logging' => [
                'level' => $this->getEnv('LOG_LEVEL', 'info'),
                'path' => $this->getEnv('LOG_PATH', 'php://stdout'),
            ],
        ];
    }

    private function getEnv(string $key, ?string $default = null): ?string
    {
        $value = $_ENV[$key] ?? $_SERVER[$key] ?? $default;
        
        if ($value === null && $default === null) {
            throw new InvalidArgumentException("Environment variable {$key} is required but not set");
        }

        return $value;
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->config[$key] ?? $default;
    }

    public function getDbConfig(): DbConfig
    {
        return DbConfig::fromArray($this->config['db']);
    }

    public function getJwksUri(): ?string
    {
        return $this->config['jwks_uri'];
    }

    public function getIssuer(): ?string
    {
        return $this->config['issuer'];
    }

    public function getAudience(): ?string
    {
        return $this->config['audience'];
    }

    public function getCacheTtl(): int
    {
        return $this->config['cache_ttl'];
    }
}