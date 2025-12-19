# Packagist Publishing Guide

This guide covers publishing AuthLib to Packagist for easy installation via Composer.

## Initial Setup

### 1. Create Packagist Account
1. Visit https://packagist.org/ and create an account
2. Verify your email address
3. Connect your GitHub account for easier package management

### 2. Submit Package
1. Go to https://packagist.org/packages/submit
2. Enter your GitHub repository URL: `https://github.com/authlib/rbac-authorization`
3. Click "Check" to validate the repository
4. Click "Submit" to register the package

### 3. Configure Auto-Updates
Set up automatic updates when you push new tags:

#### Option A: GitHub Webhook (Recommended)
1. In your Packagist package page, go to "Settings"
2. Copy the webhook URL
3. In your GitHub repository, go to Settings → Webhooks
4. Click "Add webhook"
5. Paste the Packagist webhook URL
6. Set Content type to "application/json"
7. Select "Just the push event"
8. Click "Add webhook"

#### Option B: GitHub Integration
1. In Packagist, go to your profile settings
2. Connect your GitHub account if not already done
3. Enable "Auto-update" for your repository

## Release Process

### Manual Release via Script
```bash
# Create a release (interactive)
./scripts/release.sh

# Create a specific version
./scripts/release.sh 1.2.3

# Preview changes without releasing
./scripts/release.sh --dry-run

# Create beta release
./scripts/release.sh 1.3.0-beta.1
```

### Manual Release Steps
```bash
# 1. Update CHANGELOG.md with new version
vim CHANGELOG.md

# 2. Commit changes
git add CHANGELOG.md
git commit -m "chore: prepare release v1.2.3"

# 3. Create and push tag
git tag -a v1.2.3 -m "Release version 1.2.3

## Added
- New feature descriptions

## Fixed  
- Bug fixes

## Security
- Security improvements"

git push origin main
git push origin v1.2.3
```

### Automated Release via GitHub Actions
The project includes automated release workflows:

1. **CI on PRs**: Runs tests, code style checks, and security scans
2. **Release on Tags**: Creates GitHub releases and triggers Packagist updates

To trigger automated release:
```bash
git tag v1.2.3
git push origin v1.2.3
```

## Version Management

### Semantic Versioning
Follow [Semantic Versioning](https://semver.org/):

- **MAJOR** (1.0.0 → 2.0.0): Breaking changes
- **MINOR** (1.0.0 → 1.1.0): New features, backward compatible
- **PATCH** (1.0.0 → 1.0.1): Bug fixes, backward compatible

### Pre-releases
For beta, alpha, or release candidates:
- `1.1.0-alpha.1`
- `1.1.0-beta.1`
- `1.1.0-rc.1`

## Package Configuration

### composer.json Requirements
Ensure your `composer.json` includes:

```json
{
    "name": "authlib/rbac-authorization",
    "type": "library",
    "description": "PHP RBAC authorization library with JWT/OIDC support",
    "keywords": ["rbac", "authorization", "jwt", "oidc", "security", "access-control"],
    "license": "MIT",
    "authors": [
        {
            "name": "AuthLib Contributors",
            "email": "contributors@authlib.dev"
        }
    ],
    "require": {
        "php": "^8.2"
    },
    "autoload": {
        "psr-4": {
            "authlib\\Auth\\": "src/"
        }
    },
    "extra": {
        "branch-alias": {
            "dev-main": "1.x-dev"
        }
    }
}
```

### Required Files
- `LICENSE`: MIT license file
- `README.md`: Comprehensive documentation
- `CHANGELOG.md`: Version history following Keep a Changelog format
- `composer.json`: Package metadata and dependencies

## Package Optimization

### Composer Archive
Exclude unnecessary files from Composer packages:

```json
{
    "archive": {
        "exclude": [
            "/tests",
            "/examples", 
            "/.github",
            "/scripts",
            "/.gitignore",
            "/phpunit.xml",
            "/.env.example"
        ]
    }
}
```

### Performance Tips
1. Use `--optimize-autoloader` in production
2. Enable `composer.lock` in VCS
3. Use specific version constraints in `require`

## Troubleshooting

### Common Issues

#### 1. Package Not Updating
```bash
# Check webhook status in GitHub
# Verify tag was pushed: git tag -l
# Manual update: Visit your Packagist package page and click "Update"
```

#### 2. Version Conflicts
```bash
# Delete incorrect tag locally and remotely
git tag -d v1.2.3
git push origin :refs/tags/v1.2.3

# Recreate tag
git tag v1.2.3
git push origin v1.2.3
```

#### 3. Composer Installation Issues
```bash
# Clear Composer cache
composer clear-cache

# Update package info
composer update authlib/rbac-authorization

# Check available versions
composer show authlib/rbac-authorization --all
```

### Validation Commands
```bash
# Validate composer.json syntax
composer validate

# Check package installability
composer install --dry-run

# Verify autoloading
composer dump-autoload --optimize
```

## Monitoring & Maintenance

### Package Stats
Monitor your package at:
- **Packagist**: https://packagist.org/packages/authlib/rbac-authorization
- **GitHub**: Repository Insights
- **Downloads**: Track adoption in Packagist stats

### Regular Maintenance
1. **Security Updates**: Monitor for vulnerability reports
2. **Dependency Updates**: Keep dependencies current
3. **PHP Compatibility**: Test with new PHP versions
4. **Documentation**: Keep README and examples updated

### Community Guidelines
1. Respond to issues promptly
2. Review and merge PRs
3. Maintain backward compatibility
4. Follow semantic versioning strictly
5. Write clear release notes

## Example Package Usage

Once published, users can install your package:

```bash
# Install latest stable version
composer require authlib/rbac-authorization

# Install specific version
composer require authlib/rbac-authorization:^1.0

# Install development version
composer require authlib/rbac-authorization:dev-main
```

The package will be available for use immediately:

```php
<?php
require 'vendor/autoload.php';

use authlib\Auth\Core\AuthorizationService;

$auth = new AuthorizationService(/* ... */);
```