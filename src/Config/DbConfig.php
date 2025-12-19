<?php

declare(strict_types=1);

namespace authlib\Auth\Config;

use PDO;

/**
 * Database configuration for AuthLib
 */
class DbConfig
{
    public function __construct(
        private string $host,
        private string $database,
        private string $username,
        private string $password,
        private int $port = 3306,
        private string $charset = 'utf8mb4',
        private array $options = []
    ) {
    }

    public function getHost(): string
    {
        return $this->host;
    }

    public function getDatabase(): string
    {
        return $this->database;
    }

    public function getUsername(): string
    {
        return $this->username;
    }

    public function getPassword(): string
    {
        return $this->password;
    }

    public function getPort(): int
    {
        return $this->port;
    }

    public function getCharset(): string
    {
        return $this->charset;
    }

    public function getOptions(): array
    {
        return $this->options;
    }

    public function getDsn(): string
    {
        return sprintf(
            'mysql:host=%s;port=%d;dbname=%s;charset=%s',
            $this->host,
            $this->port,
            $this->database,
            $this->charset
        );
    }

    public static function fromArray(array $config): self
    {
        return new self(
            $config['host'] ?? 'localhost',
            $config['database'] ?? '',
            $config['username'] ?? '',
            $config['password'] ?? '',
            $config['port'] ?? 3306,
            $config['charset'] ?? 'utf8mb4',
            $config['options'] ?? []
        );
    }

    /**
     * Create PDO instance from environment variables
     *
     * @return PDO Configured PDO instance
     * @throws \Exception When required environment variables are missing
     */
    public static function pdoFromEnv(): PDO
    {
        $host = getenv('DB_HOST');
        $name = getenv('DB_NAME');
        $user = getenv('DB_USER');
        $pass = getenv('DB_PASS');

        if (!$host || !$name || !$user || $pass === false) {
            throw new \Exception('Missing required database environment variables (DB_HOST, DB_NAME, DB_USER, DB_PASS)');
        }

        $dsn = sprintf('mysql:host=%s;dbname=%s;charset=utf8mb4', $host, $name);
        
        $pdo = new PDO($dsn, $user, $pass, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_PERSISTENT => false, // Disable persistent connections
        ]);

        return $pdo;
    }
}