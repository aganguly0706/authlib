# Laravel Usage Guide

This guide shows how to integrate AuthLib with Laravel applications.

## Installation

1. Install the package:
```bash
composer require authlib/authlib
```

2. Publish the configuration file (optional):
```bash
php artisan vendor:publish --provider="AuthLib\Laravel\AuthLibServiceProvider"
```

## Service Provider Registration

Add the AuthLib service provider to your `config/app.php`:

```php
'providers' => [
    // Other providers...
    AuthLib\Laravel\AuthLibServiceProvider::class,
],
```

## Configuration

### Environment Variables

Add these to your `.env` file:

```env
# OIDC Configuration
AUTH_JWKS_URI=https://your-auth-provider.com/.well-known/jwks.json
AUTH_ISSUER=https://your-auth-provider.com/
AUTH_AUDIENCE=your-application-id

# SAML Configuration
SAML_IDP_ISSUER=https://your-idp.example.com
SAML_SP_ENTITY_ID=your-application-sp-id
SAML_IDP_CERTIFICATE_FINGERPRINTS=ABC123DEF456,789GHI012JKL
SAML_MAX_ASSERTION_AGE=3600
SAML_CLOCK_SKEW=300

# Database Configuration (uses Laravel's DB config by default)
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=your_database
DB_USERNAME=your_username
DB_PASSWORD=your_password

# Caching
CACHE_DRIVER=redis
AUTH_CACHE_TTL=3600
```

### Service Container Binding

Create a service provider to bind AuthLib services:

```php
<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use authlib\Auth\Contracts\AuthorizationServiceInterface;
use authlib\Auth\Core\AuthorizationService;
use authlib\Auth\Auth\OidcTokenValidator;
use authlib\Auth\Auth\SamlAssertionValidator;
use authlib\Auth\Auth\DefaultClaimsExtractor;
use authlib\Auth\Data\PdoBindingsRepository;
use authlib\Auth\Core\PolicyEnforcer;
use authlib\Auth\Audit\LoggerAuditSink;
use authlib\Auth\Utils\JwksProvider;
use authlib\Auth\Config\DbConfig;

class AuthLibServiceProvider extends ServiceProvider
{
    public function register()
    {
        // Bind configuration
        $this->app->singleton(DbConfig::class, function ($app) {
            return DbConfig::fromArray($app['config']['database.connections.mysql']);
        });

        // Bind JWKS provider for OIDC
        $this->app->singleton(JwksProvider::class, function ($app) {
            return new JwksProvider(
                config('auth.jwks_uri'),
                $app['cache.store']
            );
        });

        // Bind OIDC token validator
        $this->app->singleton(OidcTokenValidator::class, function ($app) {
            return new OidcTokenValidator(
                $app[JwksProvider::class],
                config('auth.issuer'),
                config('auth.audience')
            );
        });

        // Bind SAML assertion validator
        $this->app->singleton(SamlAssertionValidator::class, function ($app) {
            return new SamlAssertionValidator(
                config('saml.idp_issuer'),
                config('saml.sp_entity_id'),
                explode(',', config('saml.idp_certificate_fingerprints')),
                config('saml.max_assertion_age', 3600),
                config('saml.clock_skew', 300)
            );
        });

        // Bind claims extractor
        $this->app->singleton(DefaultClaimsExtractor::class);

        // Bind bindings repository
        $this->app->singleton(PdoBindingsRepository::class, function ($app) {
            return new PdoBindingsRepository(
                $app[DbConfig::class],
                $app['cache.store']
            );
        });

        // Bind policy enforcer
        $this->app->singleton(PolicyEnforcer::class, function ($app) {
            return new PolicyEnforcer([
                // Add your policies here
            ]);
        });

        // Bind audit sink
        $this->app->singleton(LoggerAuditSink::class, function ($app) {
            return new LoggerAuditSink($app['log']);
        });

        // Bind authorization service
        $this->app->singleton(AuthorizationServiceInterface::class, AuthorizationService::class);
    }
}
```

## Middleware Usage

### Basic Usage

Register the middleware in `app/Http/Kernel.php`:

```php
protected $routeMiddleware = [
    // Other middleware...
    'auth.permission' => \authlib\Auth\Middleware\LaravelAuthorize::class,
];
```

Use in routes:

```php
// Require specific permission
Route::get('/admin/users', [UserController::class, 'index'])
    ->middleware('auth.permission:user.read');

// Using helper methods
Route::delete('/admin/users/{id}', [UserController::class, 'destroy'])
    ->middleware(\authlib\Auth\Middleware\LaravelAuthorize::delete());

// Multiple permissions (any)
Route::get('/content', [ContentController::class, 'index'])
    ->middleware('auth.permission:content.read,content.moderate');
```

### Advanced Middleware Usage

```php
// Group routes with permission
Route::middleware(['auth.permission:admin'])->group(function () {
    Route::resource('users', UserController::class);
    Route::resource('roles', RoleController::class);
});

// Dynamic permissions based on route parameters
Route::get('/projects/{project}', [ProjectController::class, 'show'])
    ->middleware(function ($request, $next) {
        $permission = "project.{$request->route('project')}.read";
        return app(\authlib\Auth\Middleware\LaravelAuthorize::class)
            ->handle($request, $next, $permission);
    });
```

## Controller Usage

### Dependency Injection

```php
<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use authlib\Auth\Contracts\AuthorizationServiceInterface;

class UserController extends Controller
{
    public function __construct(
        private AuthorizationServiceInterface $authService
    ) {}

    public function index(Request $request)
    {
        $token = $request->bearerToken();
        
        if (!$this->authService->authorize($token, 'user.read')) {
            return response()->json(['error' => 'Unauthorized'], 403);
        }

        // Your logic here
    }

    public function destroy(Request $request, $id)
    {
        $token = $request->bearerToken();
        $context = [
            'resource_id' => $id,
            'ip_address' => $request->ip(),
        ];

        if (!$this->authService->authorize($token, 'user.delete', $context)) {
            return response()->json(['error' => 'Forbidden'], 403);
        }

        // Delete user logic
    }
}
```

### Helper Methods

Create a trait for common authorization patterns:

```php
<?php

namespace App\Traits;

use authlib\Auth\Contracts\AuthorizationServiceInterface;

trait HasAuthorization
{
    protected function authorize(string $permission, array $context = []): bool
    {
        $authService = app(AuthorizationServiceInterface::class);
        $token = request()->bearerToken();
        
        return $authService->authorize($token, $permission, $context);
    }

    protected function requirePermission(string $permission, array $context = []): void
    {
        if (!$this->authorize($permission, $context)) {
            abort(403, 'Insufficient permissions');
        }
    }

    protected function getUserClaims(): array
    {
        $authService = app(AuthorizationServiceInterface::class);
        $token = request()->bearerToken();
        
        if (!$token) {
            return [];
        }

        try {
            return $authService->extractClaims($token);
        } catch (\Exception $e) {
            return [];
        }
    }
}
```

## Blade Directives

Create custom Blade directives for view-level authorization:

```php
// In AppServiceProvider::boot()
Blade::directive('canPermission', function ($permission) {
    return "<?php if(app(\authlib\Auth\Contracts\AuthorizationServiceInterface::class)->authorize(request()->bearerToken(), {$permission})): ?>";
});

Blade::directive('endcanPermission', function () {
    return '<?php endif; ?>';
});
```

Usage in Blade templates:

```blade
@canPermission('user.create')
    <a href="{{ route('users.create') }}" class="btn btn-primary">Create User</a>
@endcanPermission

@canPermission('admin')
    <div class="admin-panel">
        <!-- Admin content -->
    </div>
@endcanPermission
```

## Artisan Commands

Create commands to manage permissions:

```php
<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use authlib\Auth\Data\PdoBindingsRepository;

class GrantPermission extends Command
{
    protected $signature = 'auth:grant {user} {permission}';
    protected $description = 'Grant a permission to a user';

    public function handle(PdoBindingsRepository $repository)
    {
        $userId = $this->argument('user');
        $permission = $this->argument('permission');
        
        if ($repository->bindPermissionToUser($userId, $permission)) {
            $this->info("Permission '{$permission}' granted to user '{$userId}'");
        } else {
            $this->error('Failed to grant permission');
        }
    }
}
```

## Testing

### Unit Tests

```php
<?php

namespace Tests\Feature;

use Tests\TestCase;
use authlib\Auth\Contracts\AuthorizationServiceInterface;
use Mockery;

class AuthorizationTest extends TestCase
{
    public function test_user_can_access_with_permission()
    {
        $authService = Mockery::mock(AuthorizationServiceInterface::class);
        $authService->shouldReceive('authorize')
                   ->with('fake-token', 'user.read', Mockery::any())
                   ->andReturn(true);
        
        $this->app->instance(AuthorizationServiceInterface::class, $authService);
        
        $response = $this->withHeaders([
            'Authorization' => 'Bearer fake-token',
        ])->get('/api/users');
        
        $response->assertStatus(200);
    }
}
```

## Database Migrations

Run the AuthLib migrations:

```bash
php artisan migrate --path=vendor/authlib/authlib/database/migrations
```

Or copy them to your migrations folder and customize as needed.

## SAML Authentication Usage

### SAML Configuration File

Create a dedicated SAML configuration file `config/saml.php`:

```php
<?php

return [
    'idp_issuer' => env('SAML_IDP_ISSUER'),
    'sp_entity_id' => env('SAML_SP_ENTITY_ID'),
    'idp_certificate_fingerprints' => env('SAML_IDP_CERTIFICATE_FINGERPRINTS'),
    'max_assertion_age' => env('SAML_MAX_ASSERTION_AGE', 3600),
    'clock_skew' => env('SAML_CLOCK_SKEW', 300),
    
    // Optional: Custom claim mappings
    'claim_mappings' => [
        'user_id' => 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier',
        'email' => 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
        'name' => 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
        'roles' => 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role',
    ],
];
```

### SAML Controller for SSO

```php
<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use authlib\Auth\Auth\SamlAssertionValidator;
use authlib\Auth\Auth\DefaultClaimsExtractor;
use authlib\Auth\Contracts\AuthorizationServiceInterface;

class SamlController extends Controller
{
    public function __construct(
        private SamlAssertionValidator $samlValidator,
        private DefaultClaimsExtractor $claimsExtractor,
        private AuthorizationServiceInterface $authService
    ) {}

    /**
     * Handle SAML assertion from IdP
     */
    public function acs(Request $request)
    {
        try {
            // Get SAML response from POST data
            $samlResponse = $request->input('SAMLResponse');
            
            if (!$samlResponse) {
                return redirect()->route('login')->with('error', 'Invalid SAML response');
            }

            // Decode and validate the assertion
            $decodedResponse = base64_decode($samlResponse);
            $validationResult = $this->samlValidator->validate($decodedResponse);

            if (!$validationResult->isValid()) {
                \Log::error('SAML validation failed', [
                    'errors' => $validationResult->getErrors()
                ]);
                return redirect()->route('login')->with('error', 'Authentication failed');
            }

            // Extract claims from the assertion
            $claims = $this->claimsExtractor->extractClaims($validationResult->getAssertion());

            // Create or update user based on SAML claims
            $user = $this->findOrCreateUser($claims);

            // Log the user in
            auth()->login($user);

            // Redirect to intended page or dashboard
            return redirect()->intended('/dashboard');

        } catch (\Exception $e) {
            \Log::error('SAML authentication error', [
                'message' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            
            return redirect()->route('login')->with('error', 'Authentication failed');
        }
    }

    /**
     * Initiate SAML SSO (redirect to IdP)
     */
    public function sso()
    {
        // In a real implementation, you would generate a SAML AuthnRequest
        // and redirect to your IdP's SSO URL with the request
        $idpSsoUrl = config('saml.idp_sso_url');
        $spEntityId = config('saml.sp_entity_id');
        $acsUrl = route('saml.acs');

        // Generate SAML AuthnRequest (simplified example)
        $authnRequest = $this->generateAuthnRequest($spEntityId, $acsUrl);
        $encodedRequest = base64_encode($authnRequest);

        $redirectUrl = $idpSsoUrl . '?SAMLRequest=' . urlencode($encodedRequest);
        
        return redirect($redirectUrl);
    }

    private function findOrCreateUser(array $claims): \App\Models\User
    {
        $email = $claims['email'] ?? null;
        $userId = $claims['user_id'] ?? null;

        if (!$email && !$userId) {
            throw new \Exception('No valid identifier found in SAML claims');
        }

        // Find or create user
        $user = \App\Models\User::where('email', $email)
                              ->orWhere('saml_id', $userId)
                              ->first();

        if (!$user) {
            $user = \App\Models\User::create([
                'name' => $claims['name'] ?? 'Unknown',
                'email' => $email,
                'saml_id' => $userId,
                'email_verified_at' => now(),
            ]);
        }

        // Update user roles/permissions based on SAML claims
        if (isset($claims['roles'])) {
            $this->syncUserRoles($user, $claims['roles']);
        }

        return $user;
    }

    private function syncUserRoles(\App\Models\User $user, array $roles): void
    {
        // Map SAML roles to application permissions
        $roleMapping = config('saml.role_mapping', []);
        $permissions = [];

        foreach ($roles as $role) {
            if (isset($roleMapping[$role])) {
                $permissions = array_merge($permissions, $roleMapping[$role]);
            }
        }

        // Update user permissions in AuthLib
        // This would typically involve updating the bindings repository
        // Implementation depends on your specific requirements
    }

    private function generateAuthnRequest(string $spEntityId, string $acsUrl): string
    {
        // This is a simplified example - in production you would use
        // a proper SAML library like OneLogin or LightSAML
        $id = '_' . bin2hex(random_bytes(16));
        $issueInstant = gmdate('Y-m-d\TH:i:s\Z');

        return <<<XML
<samlp:AuthnRequest 
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{$id}"
    Version="2.0"
    IssueInstant="{$issueInstant}"
    Destination="{config('saml.idp_sso_url')}"
    AssertionConsumerServiceURL="{$acsUrl}">
    <saml:Issuer>{$spEntityId}</saml:Issuer>
</samlp:AuthnRequest>
XML;
    }
}
```

### SAML Routes

Add SAML routes to `routes/web.php`:

```php
use App\Http\Controllers\Auth\SamlController;

Route::prefix('saml')->name('saml.')->group(function () {
    Route::get('/sso', [SamlController::class, 'sso'])->name('sso');
    Route::post('/acs', [SamlController::class, 'acs'])->name('acs');
    Route::post('/sls', [SamlController::class, 'sls'])->name('sls'); // Single Logout Service
});
```

### SAML Middleware

Create middleware for SAML-specific authorization:

```php
<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use authlib\Auth\Auth\SamlAssertionValidator;

class SamlAuth
{
    public function __construct(
        private SamlAssertionValidator $validator
    ) {}

    public function handle(Request $request, Closure $next)
    {
        // Check if user has valid SAML session
        if (!session()->has('saml_assertion') || $this->isAssertionExpired()) {
            return redirect()->route('saml.sso');
        }

        return $next($request);
    }

    private function isAssertionExpired(): bool
    {
        $assertionTime = session()->get('saml_assertion_time');
        $maxAge = config('saml.max_assertion_age', 3600);
        
        return !$assertionTime || (time() - $assertionTime) > $maxAge;
    }
}
```

### Testing SAML Integration

```php
<?php

namespace Tests\Feature;

use Tests\TestCase;
use authlib\Auth\Auth\SamlAssertionValidator;
use authlib\Auth\Core\ValidationResult;

class SamlAuthTest extends TestCase
{
    public function test_saml_acs_with_valid_assertion()
    {
        // Mock SAML validator
        $validator = $this->mock(SamlAssertionValidator::class);
        $validationResult = new ValidationResult(true, [], '<assertion>test</assertion>');
        
        $validator->shouldReceive('validate')
                 ->andReturn($validationResult);

        $samlResponse = base64_encode('<samlp:Response>test response</samlp:Response>');

        $response = $this->post('/saml/acs', [
            'SAMLResponse' => $samlResponse
        ]);

        $response->assertRedirect('/dashboard');
        $this->assertAuthenticated();
    }

    public function test_saml_acs_with_invalid_assertion()
    {
        $validator = $this->mock(SamlAssertionValidator::class);
        $validationResult = new ValidationResult(false, ['Invalid signature'], null);
        
        $validator->shouldReceive('validate')
                 ->andReturn($validationResult);

        $samlResponse = base64_encode('<samlp:Response>invalid response</samlp:Response>');

        $response = $this->post('/saml/acs', [
            'SAMLResponse' => $samlResponse
        ]);

        $response->assertRedirect('/login');
        $response->assertSessionHas('error');
        $this->assertGuest();
    }
}
```