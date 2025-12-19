# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release preparation
- Documentation for Packagist publishing
- Release automation workflows

## [1.0.0] - 2025-12-19

### Added
- Complete RBAC authorization library implementation
- OIDC/JWT token validation with PingFederate support
- Active Directory group integration
- Comprehensive security practices implementation
- Enhanced JWT validation with clock skew handling (±60 seconds)
- Policy versioning with bindings hash tracking
- Per-function policy enforcement with least privilege
- Input sanitization for all user inputs
- Cache TTL alignment with token expiration
- Comprehensive audit logging with policy versioning
- Database migrations and seed data
- Laravel and Slim framework integration
- Plain PHP usage examples
- PSR-6 caching support
- PSR-3 logging integration

### Security
- Default deny policy enforcement
- Prepared statements for all SQL queries
- Algorithm validation (only secure algorithms allowed)
- Token age limits and comprehensive claims validation
- Input sanitization to prevent SQL injection and log injection
- Rate limiting and observability metrics

### Documentation
- Complete API documentation
- Security practices guide
- Framework integration examples
- Troubleshooting guide
- Performance optimization recommendations