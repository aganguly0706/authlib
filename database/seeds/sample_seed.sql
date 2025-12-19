-- Sample seed data for AuthLib RBAC system
-- This provides example groups, roles, permissions, and functions for testing

-- Insert sample external groups from PingFederate
INSERT INTO Groups (GroupId, DisplayName, Source) VALUES
('ad-group-orders-readers', 'APP_Orders_Readers', 'PingFederate'),
('ad-group-orders-editors', 'APP_Orders_Editors', 'PingFederate'),
('ad-group-orders-admins', 'APP_Orders_Admins', 'PingFederate'),
('azure-group-finance', 'Finance Team', 'AzureAD'),
('adfs-group-managers', 'Department Managers', 'ADFS');

-- Insert sample application roles
INSERT INTO AppRoles (RoleName, Description) VALUES
('OrdersReader', 'Can view orders and read order details'),
('OrdersEditor', 'Can edit orders and modify order information'),
('OrdersAdmin', 'Full administrative access to orders system'),
('FinanceUser', 'Access to financial data and reports'),
('Manager', 'Management-level access across multiple systems');

-- Map external groups to internal application roles
INSERT INTO GroupRoleBindings (GroupId, RoleId) VALUES
('ad-group-orders-readers', 1),  -- Orders Readers → OrdersReader role
('ad-group-orders-editors', 2),  -- Orders Editors → OrdersEditor role
('ad-group-orders-admins', 3),   -- Orders Admins → OrdersAdmin role
('azure-group-finance', 4),      -- Finance Team → FinanceUser role
('adfs-group-managers', 5);      -- Managers → Manager role

-- Insert sample permissions
INSERT INTO Permissions (PermissionName, Description) VALUES
('Orders.View', 'View orders list and order details'),
('Orders.Edit', 'Edit orders and modify order information'),
('Orders.Delete', 'Delete orders from the system'),
('Orders.Export', 'Export orders data to external formats'),
('Finance.View', 'View financial reports and data'),
('Finance.Edit', 'Edit financial information'),
('Admin.Users', 'Manage user accounts and permissions'),
('Admin.System', 'System administration and configuration');

-- Map roles to permissions
INSERT INTO RolePermissions (RoleId, PermissionId) VALUES
-- OrdersReader role (1) → Orders.View
(1, 1),
-- OrdersEditor role (2) → Orders.View, Orders.Edit
(2, 1),
(2, 2),
-- OrdersAdmin role (3) → All Orders permissions
(3, 1),
(3, 2),
(3, 3),
(3, 4),
-- FinanceUser role (4) → Finance permissions
(4, 5),
(4, 6),
-- Manager role (5) → View permissions across systems
(5, 1),
(5, 5),
(5, 7);

-- Insert sample functions for granular access control
INSERT INTO Functions (FunctionKey, Description) VALUES
('Orders.List', 'List all orders with pagination and filtering'),
('Orders.Details', 'View detailed order information'),
('Orders.Update', 'Update existing order information'),
('Orders.Create', 'Create new orders'),
('Orders.Cancel', 'Cancel existing orders'),
('Orders.StatusUpdate', 'Update order status'),
('Orders.BulkExport', 'Export multiple orders to CSV/Excel'),
('Finance.Reports.View', 'View financial reports'),
('Finance.Data.Edit', 'Edit financial data entries'),
('Admin.Users.List', 'List system users'),
('Admin.Users.Edit', 'Edit user permissions'),
('Admin.System.Config', 'System configuration access');

-- Map permissions to specific functions
INSERT INTO PermissionFunctionBindings (PermissionId, FunctionId) VALUES
-- Orders.View permission (1) → List and Details functions
(1, 1),  -- Orders.List
(1, 2),  -- Orders.Details
-- Orders.Edit permission (2) → Update, Create, StatusUpdate functions
(2, 3),  -- Orders.Update
(2, 4),  -- Orders.Create
(2, 6),  -- Orders.StatusUpdate
-- Orders.Delete permission (3) → Cancel function
(3, 5),  -- Orders.Cancel
-- Orders.Export permission (4) → BulkExport function
(4, 7),  -- Orders.BulkExport
-- Finance.View permission (5) → Finance reports
(5, 8),  -- Finance.Reports.View
-- Finance.Edit permission (6) → Finance data editing
(6, 9),  -- Finance.Data.Edit
-- Admin.Users permission (7) → User management functions
(7, 10), -- Admin.Users.List
(7, 11), -- Admin.Users.Edit
-- Admin.System permission (8) → System configuration
(8, 12); -- Admin.System.Config

-- Insert sample user session data (for testing)
INSERT INTO UserSessions (SessionId, UserId, UserGroups, ResolvedRoles, ResolvedPermissions, TokenIssuer, TokenSubject, IpAddress, UserAgent, ExpiresAt) VALUES
('sess_001', 'john.doe@company.com', 
 '["ad-group-orders-readers"]', 
 '["OrdersReader"]', 
 '["Orders.View"]', 
 'https://auth.company.com', 
 'john.doe@company.com', 
 '192.168.1.100', 
 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36', 
 DATE_ADD(NOW(), INTERVAL 8 HOUR)),
('sess_002', 'jane.smith@company.com', 
 '["ad-group-orders-editors"]', 
 '["OrdersEditor"]', 
 '["Orders.View", "Orders.Edit"]', 
 'https://auth.company.com', 
 'jane.smith@company.com', 
 '192.168.1.101', 
 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36', 
 DATE_ADD(NOW(), INTERVAL 8 HOUR));

-- Insert sample audit log entries
INSERT INTO AuthAuditLog (EventType, UserId, SessionId, Resource, Action, Result, GroupsInvolved, RolesInvolved, PermissionsInvolved, IpAddress, UserAgent, Context) VALUES
('permission_check', 'john.doe@company.com', 'sess_001', 'orders', 'list', 'granted',
 '["ad-group-orders-readers"]', '["OrdersReader"]', '["Orders.View"]',
 '192.168.1.100', 'Mozilla/5.0...', '{"request_id": "req_001", "endpoint": "/api/orders"}'),
('permission_check', 'jane.smith@company.com', 'sess_002', 'orders', 'update', 'granted',
 '["ad-group-orders-editors"]', '["OrdersEditor"]', '["Orders.Edit"]',
 '192.168.1.101', 'Mozilla/5.0...', '{"request_id": "req_002", "endpoint": "/api/orders/123", "order_id": 123}'),
('permission_check', 'guest.user@company.com', NULL, 'orders', 'delete', 'denied',
 '[]', '[]', '[]',
 '192.168.1.102', 'PostmanRuntime/7.29.0', '{"request_id": "req_003", "reason": "no_permissions"}');

-- Insert sample cache entries
INSERT INTO PermissionCache (CacheKey, UserId, CacheData, ExpiresAt) VALUES
('user_perms_john.doe@company.com_default', 'john.doe@company.com',
 '{"groups": ["ad-group-orders-readers"], "roles": ["OrdersReader"], "permissions": ["Orders.View"], "functions": ["Orders.List", "Orders.Details"]}',
 DATE_ADD(NOW(), INTERVAL 1 HOUR)),
('user_perms_jane.smith@company.com_default', 'jane.smith@company.com',
 '{"groups": ["ad-group-orders-editors"], "roles": ["OrdersEditor"], "permissions": ["Orders.View", "Orders.Edit"], "functions": ["Orders.List", "Orders.Details", "Orders.Update", "Orders.Create", "Orders.StatusUpdate"]}',
 DATE_ADD(NOW(), INTERVAL 1 HOUR));

-- Verify data integrity with some sample queries (commented out for production)
-- These can be uncommented for testing and verification

/*
-- Check group to role mappings
SELECT g.DisplayName, ar.RoleName 
FROM Groups g 
JOIN GroupRoleBindings grb ON g.GroupId = grb.GroupId 
JOIN AppRoles ar ON grb.RoleId = ar.RoleId;

-- Check role permissions
SELECT ar.RoleName, p.PermissionName, p.Description
FROM AppRoles ar
JOIN RolePermissions rp ON ar.RoleId = rp.RoleId
JOIN Permissions p ON rp.PermissionId = p.PermissionId
ORDER BY ar.RoleName, p.PermissionName;

-- Check permission to function mappings
SELECT p.PermissionName, f.FunctionKey, f.Description
FROM Permissions p
JOIN PermissionFunctionBindings pfb ON p.PermissionId = pfb.PermissionId
JOIN Functions f ON pfb.FunctionId = f.FunctionId
ORDER BY p.PermissionName, f.FunctionKey;

-- Check complete access hierarchy for a specific group
SELECT 
    g.DisplayName AS GroupName,
    ar.RoleName,
    p.PermissionName,
    f.FunctionKey
FROM Groups g
JOIN GroupRoleBindings grb ON g.GroupId = grb.GroupId
JOIN AppRoles ar ON grb.RoleId = ar.RoleId
JOIN RolePermissions rp ON ar.RoleId = rp.RoleId
JOIN Permissions p ON rp.PermissionId = p.PermissionId
JOIN PermissionFunctionBindings pfb ON p.PermissionId = pfb.PermissionId
JOIN Functions f ON pfb.FunctionId = f.FunctionId
WHERE g.GroupId = 'ad-group-orders-editors'
ORDER BY f.FunctionKey;
*/