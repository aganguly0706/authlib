#!/bin/bash

# AuthLib Release Script
# Usage: ./scripts/release.sh [version] [--dry-run]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Parse arguments
VERSION=""
DRY_RUN=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [version] [--dry-run]"
            echo ""
            echo "Examples:"
            echo "  $0 1.2.3              # Release version 1.2.3"
            echo "  $0 1.3.0-beta.1       # Release beta version"
            echo "  $0 --dry-run          # Preview next release"
            echo ""
            echo "Options:"
            echo "  --dry-run    Preview changes without creating release"
            echo "  -h, --help   Show this help message"
            exit 0
            ;;
        *)
            if [[ -z "$VERSION" ]]; then
                VERSION="$1"
            else
                error "Unknown argument: $1"
            fi
            shift
            ;;
    esac
done

# Validate version format
validate_version() {
    if [[ ! $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9]+(\.[0-9]+)?)?$ ]]; then
        error "Invalid version format: $1. Must follow semantic versioning (e.g., 1.2.3 or 1.3.0-beta.1)"
    fi
}

# Get current version from git tags
get_current_version() {
    git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//' || echo "0.0.0"
}

# Compare versions
version_greater() {
    # Simple version comparison - could be enhanced with proper semver comparison
    printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n1 | grep -q "^$1$"
}

# Check if working directory is clean
check_git_status() {
    if [[ -n $(git status --porcelain) ]]; then
        error "Working directory is not clean. Please commit or stash changes before releasing."
    fi

    # Ensure we're on main or develop branch
    CURRENT_BRANCH=$(git branch --show-current)
    if [[ "$CURRENT_BRANCH" != "main" && "$CURRENT_BRANCH" != "develop" ]]; then
        warn "Not on main or develop branch (current: $CURRENT_BRANCH)"
        read -p "Continue anyway? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            error "Release cancelled"
        fi
    fi
}

# Update changelog
update_changelog() {
    local version=$1
    local date=$(date +%Y-%m-%d)
    
    log "Updating CHANGELOG.md for version $version"
    
    # Check if version already exists in changelog
    if grep -q "## \[$version\]" CHANGELOG.md; then
        log "Version $version already exists in CHANGELOG.md"
        return
    fi
    
    # Update [Unreleased] section to new version
    sed -i.bak "s/## \[Unreleased\]/## [Unreleased]\n\n## [$version] - $date/" CHANGELOG.md
    rm -f CHANGELOG.md.bak
    
    log "Please review and edit CHANGELOG.md to add release notes for version $version"
    
    if [[ "$DRY_RUN" == false ]]; then
        read -p "Open CHANGELOG.md in editor? [Y/n] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            ${EDITOR:-nano} CHANGELOG.md
        fi
    fi
}

# Run tests
run_tests() {
    log "Running tests..."
    if ! composer test 2>/dev/null; then
        if [[ -f "vendor/bin/phpunit" ]]; then
            vendor/bin/phpunit
        else
            warn "No tests found. Consider adding tests before releasing."
        fi
    fi
}

# Update version in composer.json
update_composer_version() {
    local version=$1
    
    if [[ -f "composer.json" ]]; then
        log "Updating version in composer.json"
        if command -v jq >/dev/null 2>&1; then
            jq --arg version "$version" '.version = $version' composer.json > composer.json.tmp
            mv composer.json.tmp composer.json
        else
            warn "jq not found. Please manually update version in composer.json"
        fi
    fi
}

# Create git tag
create_tag() {
    local version=$1
    local tag="v$version"
    
    log "Creating git tag: $tag"
    
    # Extract release notes from changelog
    local release_notes=$(awk -v version="$version" '
        /^## \[/ { 
            if ($0 ~ "\\[" version "\\]") { 
                found=1; 
                next; 
            } else if (found) { 
                exit; 
            } 
        }
        found && !/^## / { print }
    ' CHANGELOG.md | sed '/^$/d' | head -20)
    
    if [[ -z "$release_notes" ]]; then
        release_notes="Release version $version"
    fi
    
    if [[ "$DRY_RUN" == false ]]; then
        git add -A
        git commit -m "chore: prepare release $version" || true
        git tag -a "$tag" -m "Release version $version

$release_notes"
    else
        log "DRY RUN: Would create tag $tag with message:"
        echo "$release_notes"
    fi
}

# Push to remote
push_release() {
    local version=$1
    local tag="v$version"
    
    if [[ "$DRY_RUN" == false ]]; then
        log "Pushing release to origin..."
        git push origin $(git branch --show-current)
        git push origin "$tag"
        log "Release $version pushed successfully!"
        log "GitHub will automatically create a release and trigger Packagist update"
    else
        log "DRY RUN: Would push tag $tag to origin"
    fi
}

# Main release process
main() {
    cd "$PROJECT_ROOT"
    
    log "Starting release process for AuthLib RBAC Authorization Library"
    
    # Get current version if not provided
    if [[ -z "$VERSION" ]]; then
        CURRENT_VERSION=$(get_current_version)
        log "Current version: $CURRENT_VERSION"
        echo
        echo "Enter new version (semantic versioning):"
        echo "  Examples: 1.0.0, 1.1.0, 1.0.1, 1.1.0-beta.1"
        read -p "New version: " VERSION
    fi
    
    validate_version "$VERSION"
    
    CURRENT_VERSION=$(get_current_version)
    
    # Check if new version is greater than current
    if [[ "$VERSION" != *"-"* ]] && ! version_greater "$VERSION" "$CURRENT_VERSION"; then
        error "New version ($VERSION) must be greater than current version ($CURRENT_VERSION)"
    fi
    
    log "Releasing version: $VERSION"
    log "Current version: $CURRENT_VERSION"
    
    if [[ "$DRY_RUN" == false ]]; then
        check_git_status
    fi
    
    # Update files
    update_changelog "$VERSION"
    update_composer_version "$VERSION"
    
    # Run tests
    run_tests
    
    # Create and push release
    create_tag "$VERSION"
    push_release "$VERSION"
    
    if [[ "$DRY_RUN" == false ]]; then
        echo
        log "✅ Release $VERSION completed successfully!"
        log "🔗 GitHub Release: https://github.com/authlib/rbac-authorization/releases/tag/v$VERSION"
        log "📦 Packagist: https://packagist.org/packages/authlib/rbac-authorization"
        log "📚 Documentation: Update docs if needed"
        echo
        log "Next steps:"
        log "1. Verify the GitHub release was created"
        log "2. Check that Packagist updated automatically"
        log "3. Update documentation if needed"
        log "4. Announce the release"
    else
        echo
        log "DRY RUN completed. No changes were made."
    fi
}

# Run main function
main "$@"