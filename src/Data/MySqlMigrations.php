<?php

declare(strict_types=1);

namespace authlib\Auth\Data;

use authlib\Auth\Config\DbConfig;
use PDO;
use PDOException;

/**
 * MySQL database migrations for AuthLib
 */
class MySqlMigrations
{
    private PDO $pdo;

    public function __construct(DbConfig $config)
    {
        $this->pdo = new PDO(
            $config->getDsn(),
            $config->getUsername(),
            $config->getPassword(),
            [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES {$config->getCharset()}",
            ]
        );
    }

    /**
     * Run all migrations
     */
    public function migrate(): void
    {
        $this->createMigrationsTable();
        $this->runMigration('0001_init', [$this, 'migration0001Init']);
    }

    /**
     * Initial database schema
     */
    public function migration0001Init(): void
    {
        // User roles table
        $this->pdo->exec("
            CREATE TABLE IF NOT EXISTS user_roles (
                id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                user_id VARCHAR(255) NOT NULL,
                role VARCHAR(100) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY unique_user_role (user_id, role),
                INDEX idx_user_id (user_id),
                INDEX idx_role (role)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        ");

        // User permissions table
        $this->pdo->exec("
            CREATE TABLE IF NOT EXISTS user_permissions (
                id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                user_id VARCHAR(255) NOT NULL,
                permission VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY unique_user_permission (user_id, permission),
                INDEX idx_user_id (user_id),
                INDEX idx_permission (permission)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        ");

        // Role permissions table
        $this->pdo->exec("
            CREATE TABLE IF NOT EXISTS role_permissions (
                id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                role VARCHAR(100) NOT NULL,
                permission VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY unique_role_permission (role, permission),
                INDEX idx_role (role),
                INDEX idx_permission (permission)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        ");

        // Audit log table
        $this->pdo->exec("
            CREATE TABLE IF NOT EXISTS auth_audit_log (
                id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                event_type VARCHAR(50) NOT NULL,
                user_id VARCHAR(255),
                resource VARCHAR(255),
                action VARCHAR(100),
                result ENUM('granted', 'denied', 'error') NOT NULL,
                ip_address VARCHAR(45),
                user_agent TEXT,
                context JSON,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_event_type (event_type),
                INDEX idx_user_id (user_id),
                INDEX idx_created_at (created_at),
                INDEX idx_result (result)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        ");
    }

    /**
     * Create migrations tracking table
     */
    private function createMigrationsTable(): void
    {
        $this->pdo->exec("
            CREATE TABLE IF NOT EXISTS authlib_migrations (
                id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                migration VARCHAR(255) NOT NULL UNIQUE,
                executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        ");
    }

    /**
     * Run a specific migration if not already executed
     */
    private function runMigration(string $name, callable $migration): void
    {
        $stmt = $this->pdo->prepare("SELECT COUNT(*) FROM authlib_migrations WHERE migration = ?");
        $stmt->execute([$name]);
        
        if ($stmt->fetchColumn() == 0) {
            try {
                $this->pdo->beginTransaction();
                
                call_user_func($migration);
                
                $stmt = $this->pdo->prepare("INSERT INTO authlib_migrations (migration) VALUES (?)");
                $stmt->execute([$name]);
                
                $this->pdo->commit();
                
                echo "Migration {$name} executed successfully.\n";
            } catch (PDOException $e) {
                $this->pdo->rollBack();
                throw new PDOException("Migration {$name} failed: " . $e->getMessage(), 0, $e);
            }
        }
    }

    /**
     * Get list of executed migrations
     */
    public function getExecutedMigrations(): array
    {
        $stmt = $this->pdo->query("SELECT migration, executed_at FROM authlib_migrations ORDER BY executed_at");
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
}