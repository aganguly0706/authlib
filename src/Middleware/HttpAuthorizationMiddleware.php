<?php

declare(strict_types=1);

namespace AuthLib\Middleware;

use AuthLib\Core\PolicyEnforcer;
use AuthLib\Contracts\ClaimsExtractorInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Laminas\Diactoros\Response;
use Laminas\Diactoros\Response\JsonResponse;

/**
 * PSR-15 middleware for HTTP authorization
 * 
 * Validates Bearer tokens and enforces permissions using PolicyEnforcer
 */
final class HttpAuthorizationMiddleware implements MiddlewareInterface
{
    public function __construct(
        private readonly PolicyEnforcer $enforcer,
        private readonly string $permission
    ) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $auth = $request->getHeaderLine('Authorization');
        
        if (!preg_match('/^Bearer\s+(.+)$/', $auth, $m)) {
            return new Response(401, ['Content-Type' => 'application/json'],
                json_encode(['error' => 'Missing bearer token']));
        }
        
        if (!$this->enforcer->requirePermission($m[1], $this->permission)) {
            return new Response(403, ['Content-Type' => 'application/json'],
                json_encode(['error' => 'Forbidden', 'permission' => $this->permission]));
        }
        
        return $handler->handle($request);
    }
}