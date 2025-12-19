<?php

declare(strict_types=1);

namespace authlib\Auth\Tests;

use PHPUnit\Framework\TestCase;
use authlib\Auth\Middleware\LaravelAuthorize;
use authlib\Auth\Core\PolicyEnforcer;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Http\JsonResponse;
use Closure;

/**
 * Test suite for LaravelAuthorize middleware
 */
class LaravelAuthorizeTest extends TestCase
{
    private PolicyEnforcer $enforcer;
    private LaravelAuthorize $middleware;

    protected function setUp(): void
    {
        $this->enforcer = $this->createMock(PolicyEnforcer::class);
        $this->middleware = new LaravelAuthorize($this->enforcer);
    }

    public function testHandleWithValidTokenAndPermission(): void
    {
        $request = Request::create('/api/orders', 'GET');
        $request->headers->set('Authorization', 'Bearer valid-token');
        
        $this->enforcer
            ->expects($this->once())
            ->method('requirePermission')
            ->with('valid-token', 'Orders.Edit')
            ->willReturn(true);

        $this->enforcer
            ->expects($this->once())
            ->method('getClaims')
            ->with('valid-token')
            ->willReturn(['user_id' => 'user123', 'sub' => 'user123']);

        $next = function ($req) {
            $this->assertEquals('user123', $req->attributes->get('auth_user_id'));
            $this->assertEquals(['user_id' => 'user123', 'sub' => 'user123'], $req->attributes->get('auth_claims'));
            return new Response('Success');
        };

        $response = $this->middleware->handle($request, $next, 'Orders.Edit');

        $this->assertInstanceOf(Response::class, $response);
        $this->assertEquals('Success', $response->getContent());
    }

    public function testHandleWithMissingAuthorizationHeader(): void
    {
        $request = Request::create('/api/orders', 'GET');
        
        $next = function () {
            $this->fail('Next middleware should not be called');
        };

        $response = $this->middleware->handle($request, $next, 'Orders.Edit');

        $this->assertInstanceOf(JsonResponse::class, $response);
        $this->assertEquals(401, $response->getStatusCode());
        
        $data = json_decode($response->getContent(), true);
        $this->assertEquals('Missing Authorization header', $data['error']);
    }

    public function testHandleWithInvalidBearerFormat(): void
    {
        $request = Request::create('/api/orders', 'GET');
        $request->headers->set('Authorization', 'Basic dXNlcjpwYXNz');
        
        $next = function () {
            $this->fail('Next middleware should not be called');
        };

        $response = $this->middleware->handle($request, $next, 'Orders.Edit');

        $this->assertInstanceOf(JsonResponse::class, $response);
        $this->assertEquals(401, $response->getStatusCode());
        
        $data = json_decode($response->getContent(), true);
        $this->assertEquals('Missing bearer token', $data['error']);
    }

    public function testHandleWithInsufficientPermissions(): void
    {
        $request = Request::create('/api/orders', 'GET');
        $request->headers->set('Authorization', 'Bearer token-without-permission');
        
        $this->enforcer
            ->expects($this->once())
            ->method('requirePermission')
            ->with('token-without-permission', 'Orders.Edit')
            ->willReturn(false);

        $next = function () {
            $this->fail('Next middleware should not be called');
        };

        $response = $this->middleware->handle($request, $next, 'Orders.Edit');

        $this->assertInstanceOf(JsonResponse::class, $response);
        $this->assertEquals(403, $response->getStatusCode());
        
        $data = json_decode($response->getContent(), true);
        $this->assertEquals('Forbidden', $data['error']);
        $this->assertEquals('Orders.Edit', $data['permission']);
    }

    public function testHandleWithInvalidToken(): void
    {
        $request = Request::create('/api/orders', 'GET');
        $request->headers->set('Authorization', 'Bearer invalid-token');
        
        $this->enforcer
            ->expects($this->once())
            ->method('requirePermission')
            ->with('invalid-token', 'Orders.Edit')
            ->willThrowException(new \Exception('Token validation failed'));

        $next = function () {
            $this->fail('Next middleware should not be called');
        };

        $response = $this->middleware->handle($request, $next, 'Orders.Edit');

        $this->assertInstanceOf(JsonResponse::class, $response);
        $this->assertEquals(401, $response->getStatusCode());
        
        $data = json_decode($response->getContent(), true);
        $this->assertEquals('Invalid token', $data['error']);
        $this->assertStringContains('Token validation failed', $data['message']);
    }
}