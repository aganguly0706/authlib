-- AuthLib RBAC Core Tables Migration
-- This creates the core tables for role-based access control with external group integration

-- Groups table: External groups from identity providers (PingFederate, AzureAD, ADFS)
CREATE TABLE Groups (
    GroupId VARCHAR(64) PRIMARY KEY COMMENT 'External group identifier from IdP',
    DisplayName VARCHAR(256) NOT NULL COMMENT 'Human-readable group name',
    Source VARCHAR(32) NOT NULL DEFAULT 'PingFederate' COMMENT 'Identity provider source',
    CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'When group was first seen',
    INDEX idx_groups_source (Source),
    INDEX idx_groups_display_name (DisplayName)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='External identity provider groups';

-- Application roles table: Internal application roles
CREATE TABLE AppRoles (
    RoleId INT PRIMARY KEY AUTO_INCREMENT COMMENT 'Internal role identifier',
    RoleName VARCHAR(128) NOT NULL UNIQUE COMMENT 'Role name (e.g., Admin, Editor)',
    Description VARCHAR(512) COMMENT 'Role description',
    CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'When role was created',
    INDEX idx_app_roles_name (RoleName)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Application-specific roles';

-- Group to role bindings: Maps external groups to internal roles
CREATE TABLE GroupRoleBindings (
    GroupId VARCHAR(64) NOT NULL COMMENT 'External group ID',
    RoleId INT NOT NULL COMMENT 'Internal role ID',
    CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'When binding was created',
    PRIMARY KEY (GroupId, RoleId),
    CONSTRAINT fk_grb_group FOREIGN KEY (GroupId) REFERENCES Groups(GroupId) ON DELETE CASCADE,
    CONSTRAINT fk_grb_role FOREIGN KEY (RoleId) REFERENCES AppRoles(RoleId) ON DELETE CASCADE,
    INDEX idx_grb_group (GroupId),
    INDEX idx_grb_role (RoleId)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Maps external groups to application roles';

-- Permissions table: High-level permissions
CREATE TABLE Permissions (
    PermissionId INT PRIMARY KEY AUTO_INCREMENT COMMENT 'Permission identifier',
    PermissionName VARCHAR(128) NOT NULL UNIQUE COMMENT 'Permission name (e.g., Orders.View, Orders.Edit)',
    Description VARCHAR(512) COMMENT 'Permission description',
    CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'When permission was created',
    INDEX idx_permissions_name (PermissionName)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Application permissions';

-- Role to permission mappings
CREATE TABLE RolePermissions (
    RoleId INT NOT NULL COMMENT 'Role ID',
    PermissionId INT NOT NULL COMMENT 'Permission ID',
    CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'When mapping was created',
    PRIMARY KEY (RoleId, PermissionId),
    CONSTRAINT fk_rp_role FOREIGN KEY (RoleId) REFERENCES AppRoles(RoleId) ON DELETE CASCADE,
    CONSTRAINT fk_rp_perm FOREIGN KEY (PermissionId) REFERENCES Permissions(PermissionId) ON DELETE CASCADE,
    INDEX idx_rp_role (RoleId),
    INDEX idx_rp_permission (PermissionId)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Maps roles to permissions';

-- Functions table: Granular function-level access control
CREATE TABLE Functions (
    FunctionId INT PRIMARY KEY AUTO_INCREMENT COMMENT 'Function identifier',
    FunctionKey VARCHAR(128) NOT NULL UNIQUE COMMENT 'Function key (e.g., Orders.List, Orders.Update)',
    Description VARCHAR(512) COMMENT 'Function description',
    CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'When function was created',
    INDEX idx_functions_key (FunctionKey)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Application functions for granular access control';

-- Permission to function mappings: Links permissions to specific functions
CREATE TABLE PermissionFunctionBindings (
    PermissionId INT NOT NULL COMMENT 'Permission ID',
    FunctionId INT NOT NULL COMMENT 'Function ID',
    CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'When binding was created',
    PRIMARY KEY (PermissionId, FunctionId),
    CONSTRAINT fk_pfb_perm FOREIGN KEY (PermissionId) REFERENCES Permissions(PermissionId) ON DELETE CASCADE,
    CONSTRAINT fk_pfb_func FOREIGN KEY (FunctionId) REFERENCES Functions(FunctionId) ON DELETE CASCADE,
    INDEX idx_pfb_permission (PermissionId),
    INDEX idx_pfb_function (FunctionId)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Maps permissions to specific functions';

-- User sessions table: Track active user sessions and their resolved permissions
CREATE TABLE UserSessions (
    SessionId VARCHAR(128) PRIMARY KEY COMMENT 'Session identifier',
    UserId VARCHAR(255) NOT NULL COMMENT 'User identifier from token',
    UserGroups JSON COMMENT 'User groups from token claims',
    ResolvedRoles JSON COMMENT 'Resolved application roles',
    ResolvedPermissions JSON COMMENT 'Resolved permissions',
    TokenIssuer VARCHAR(255) COMMENT 'Token issuer',
    TokenSubject VARCHAR(255) COMMENT 'Token subject',
    IpAddress VARCHAR(45) COMMENT 'Client IP address',
    UserAgent TEXT COMMENT 'Client user agent',
    CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Session start time',
    LastAccessedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Last activity time',
    ExpiresAt TIMESTAMP COMMENT 'Session expiry time',
    INDEX idx_user_sessions_user_id (UserId),
    INDEX idx_user_sessions_expires (ExpiresAt),
    INDEX idx_user_sessions_last_access (LastAccessedAt)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Active user sessions with resolved permissions';

-- Audit log table: Records authorization events
CREATE TABLE AuthAuditLog (
    LogId BIGINT PRIMARY KEY AUTO_INCREMENT COMMENT 'Log entry identifier',
    EventType VARCHAR(50) NOT NULL COMMENT 'Type of event (permission_check, token_validation, etc.)',
    UserId VARCHAR(255) COMMENT 'User identifier involved in the event',
    SessionId VARCHAR(128) COMMENT 'Session identifier if available',
    Resource VARCHAR(255) COMMENT 'Resource being accessed',
    Action VARCHAR(100) COMMENT 'Action being performed',
    Result ENUM('granted', 'denied', 'error') NOT NULL COMMENT 'Result of the authorization check',
    GroupsInvolved JSON COMMENT 'Groups involved in the decision',
    RolesInvolved JSON COMMENT 'Roles involved in the decision',
    PermissionsInvolved JSON COMMENT 'Permissions involved in the decision',
    IpAddress VARCHAR(45) COMMENT 'Client IP address',
    UserAgent TEXT COMMENT 'Client user agent string',
    Context JSON COMMENT 'Additional context data',
    CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'When event occurred',
    INDEX idx_audit_event_type (EventType),
    INDEX idx_audit_user_id (UserId),
    INDEX idx_audit_session_id (SessionId),
    INDEX idx_audit_created_at (CreatedAt),
    INDEX idx_audit_result (Result),
    INDEX idx_audit_resource (Resource),
    CONSTRAINT fk_audit_session FOREIGN KEY (SessionId) REFERENCES UserSessions(SessionId) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Authorization audit log';

-- Cache table: For caching resolved permissions and group memberships
CREATE TABLE PermissionCache (
    CacheKey VARCHAR(255) PRIMARY KEY COMMENT 'Cache key (user_id + context hash)',
    UserId VARCHAR(255) NOT NULL COMMENT 'User identifier',
    CacheData JSON NOT NULL COMMENT 'Cached permission data',
    CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'When cache entry was created',
    ExpiresAt TIMESTAMP NOT NULL COMMENT 'When cache entry expires',
    INDEX idx_cache_user_id (UserId),
    INDEX idx_cache_expires (ExpiresAt)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Permission resolution cache';

-- Migration tracking table
CREATE TABLE AuthlibMigrations (
    Id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY COMMENT 'Migration ID',
    Migration VARCHAR(255) NOT NULL UNIQUE COMMENT 'Migration name',
    ExecutedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'When migration was executed'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Migration tracking';

-- Insert initial migration record
INSERT INTO AuthlibMigrations (Migration) VALUES ('0001_init');

-- Create indexes for performance optimization
CREATE INDEX idx_groups_composite ON Groups(Source, DisplayName);
CREATE INDEX idx_user_sessions_composite ON UserSessions(UserId, ExpiresAt);
CREATE INDEX idx_audit_composite ON AuthAuditLog(UserId, EventType, CreatedAt);

-- Add check constraints for data validation
ALTER TABLE Groups ADD CONSTRAINT chk_groups_source 
    CHECK (Source IN ('PingFederate', 'AzureAD', 'ADFS', 'Okta', 'OneLogin', 'Custom'));

ALTER TABLE AuthAuditLog ADD CONSTRAINT chk_audit_result 
    CHECK (Result IN ('granted', 'denied', 'error'));

-- Comments for better documentation
ALTER TABLE Groups COMMENT = 'External identity provider groups mapped to internal roles';
ALTER TABLE AppRoles COMMENT = 'Application-specific roles with associated permissions';
ALTER TABLE GroupRoleBindings COMMENT = 'Many-to-many mapping between external groups and internal roles';
ALTER TABLE Permissions COMMENT = 'High-level permissions that can be assigned to roles';
ALTER TABLE RolePermissions COMMENT = 'Many-to-many mapping between roles and permissions';
ALTER TABLE Functions COMMENT = 'Granular function-level access control points';
ALTER TABLE PermissionFunctionBindings COMMENT = 'Many-to-many mapping between permissions and functions';