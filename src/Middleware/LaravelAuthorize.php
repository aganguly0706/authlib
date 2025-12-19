<?php

declare(strict_types=1);

namespace AuthLib\Middleware;

use AuthLib\Contracts\AuthorizationServiceInterface;
use AuthLib\Core\PolicyEnforcer;
use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

/**
 * Laravel middleware for authorization using PolicyEnforcer
 * Usage: ->middleware('perm:Orders.Edit')
 */
final class LaravelAuthorize
{
    public function __construct(
        private readonly PolicyEnforcer $enforcer
    ) {}

    /**
     * Handle an incoming request.
     *
     * @param Request $request
     * @param Closure $next
     * @param string $permission The required permission (e.g., 'Orders.Edit')
     * @return mixed
     */
    public function handle(Request $request, Closure $next, string $permission)
    {
        // Extract Authorization header
        $authHeader = $request->header('Authorization');
        
        if (empty($authHeader)) {
            return $this->unauthorized('Missing Authorization header');
        }

        // Extract bearer token
        if (!preg_match('/^Bearer\s+(.+)$/', $authHeader, $matches)) {
            return $this->unauthorized('Missing bearer token');
        }

        $token = $matches[1];

        try {
            // Check permission using PolicyEnforcer
            if (!$this->enforcer->requirePermission($token, $permission)) {
                return $this->forbidden($permission);
            }

            // Add decoded claims to request for downstream usage
            $claims = $this->enforcer->getClaims($token);
            if ($claims) {
                $request->merge(['auth_claims' => $claims]);
                $request->merge(['auth_user_id' => $claims['user_id'] ?? null]);
                
                // Also set request attributes if using newer Laravel versions
                if (method_exists($request, 'attributes')) {
                    $request->attributes->set('auth_claims', $claims);
                    $request->attributes->set('auth_user_id', $claims['user_id'] ?? null);
                }
            }

        } catch (Exception $e) {
            return $this->unauthorized('Invalid token: ' . $e->getMessage());
        }

        return $next($request);
    }

    /**
     * Create a 401 Unauthorized response
     */
    private function unauthorized(string $message): JsonResponse
    {
        return new JsonResponse([
            'error' => 'Unauthorized',
            'message' => $message
        ], Response::HTTP_UNAUTHORIZED);
    }

    /**
     * Create a 403 Forbidden response
     */
    private function forbidden(string $permission): JsonResponse
    {
        return new JsonResponse([
            'error' => 'Forbidden',
            'permission' => $permission,
            'message' => 'Access denied for the requested resource'
        ], Response::HTTP_FORBIDDEN);
    }

    /**
     * Get the PolicyEnforcer instance (for testing)
     */
    public function getEnforcer(): PolicyEnforcer
    {
        return $this->enforcer;
    }
}