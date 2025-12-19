<?php

declare(strict_types=1);

namespace authlib\Auth\Tests;

use PHPUnit\Framework\TestCase;
use authlib\Auth\Middleware\HttpAuthorizationMiddleware;
use authlib\Auth\Core\PolicyEnforcer;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Http\Message\ResponseInterface;
use Nyholm\Psr7\ServerRequest;
use Nyholm\Psr7\Response;
use Exception;

/**
 * Test suite for HttpAuthorizationMiddleware
 */
class HttpAuthorizationMiddlewareTest extends TestCase
{
    private PolicyEnforcer $mockEnforcer;
    private RequestHandlerInterface $mockHandler;
    private HttpAuthorizationMiddleware $middleware;
    private string $testPermission = 'Orders.Read';

    protected function setUp(): void
    {
        $this->mockEnforcer = $this->createMock(PolicyEnforcer::class);
        $this->mockHandler = $this->createMock(RequestHandlerInterface::class);
        $this->middleware = new HttpAuthorizationMiddleware($this->mockEnforcer, $this->testPermission);
    }

    public function testProcessWithValidTokenAndPermission(): void
    {
        $request = new ServerRequest('GET', '/api/orders');
        $request = $request->withHeader('Authorization', 'Bearer valid-token-123');
        
        $expectedResponse = new Response(200, [], 'Success');
        
        $this->mockEnforcer
            ->expects($this->once())
            ->method('requirePermission')
            ->with('valid-token-123', $this->testPermission)
            ->willReturn(true);

        $this->mockEnforcer
            ->expects($this->once())
            ->method('getClaims')
            ->with('valid-token-123')
            ->willReturn(['user_id' => 'user123', 'sub' => 'user123']);

        $this->mockHandler
            ->expects($this->once())
            ->method('handle')
            ->with($this->callback(function ($req) {
                return $req->getAttribute('auth_claims') === ['user_id' => 'user123', 'sub' => 'user123'] &&
                       $req->getAttribute('auth_user_id') === 'user123';
            }))
            ->willReturn($expectedResponse);

        $response = $this->middleware->process($request, $this->mockHandler);

        $this->assertSame($expectedResponse, $response);
    }

    public function testProcessWithMissingAuthorizationHeader(): void
    {
        $request = new ServerRequest('GET', '/api/orders');
        
        $response = $this->middleware->process($request, $this->mockHandler);
        
        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals('application/json', $response->getHeaderLine('Content-Type'));
        
        $body = json_decode((string) $response->getBody(), true);
        $this->assertEquals('Missing Authorization header', $body['error']);
    }

    public function testProcessWithInvalidBearerFormat(): void
    {
        $request = new ServerRequest('GET', '/api/orders');
        $request = $request->withHeader('Authorization', 'Basic dXNlcjpwYXNz');
        
        $response = $this->middleware->process($request, $this->mockHandler);
        
        $this->assertEquals(401, $response->getStatusCode());
        
        $body = json_decode((string) $response->getBody(), true);
        $this->assertEquals('Missing bearer token', $body['error']);
    }

    public function testProcessWithInsufficientPermissions(): void
    {
        $request = new ServerRequest('GET', '/api/orders');
        $request = $request->withHeader('Authorization', 'Bearer token-without-permission');
        
        $this->mockEnforcer
            ->expects($this->once())
            ->method('requirePermission')
            ->with('token-without-permission', $this->testPermission)
            ->willReturn(false);

        $response = $this->middleware->process($request, $this->mockHandler);
        
        $this->assertEquals(403, $response->getStatusCode());
        
        $body = json_decode((string) $response->getBody(), true);
        $this->assertEquals('Forbidden', $body['error']);
        $this->assertEquals($this->testPermission, $body['permission']);
    }

    public function testProcessWithInvalidToken(): void
    {
        $request = new ServerRequest('GET', '/api/orders');
        $request = $request->withHeader('Authorization', 'Bearer invalid-token');
        
        $this->mockEnforcer
            ->expects($this->once())
            ->method('requirePermission')
            ->with('invalid-token', $this->testPermission)
            ->willThrowException(new Exception('Token validation failed'));

        $response = $this->middleware->process($request, $this->mockHandler);
        
        $this->assertEquals(401, $response->getStatusCode());
        
        $body = json_decode((string) $response->getBody(), true);
        $this->assertEquals('Invalid token', $body['error']);
        $this->assertStringContains('Token validation failed', $body['message']);
    }

    public function testGetRequiredPermission(): void
    {
        $this->assertEquals($this->testPermission, $this->middleware->getRequiredPermission());
    }

    public function testProcessWithEmptyAuthorizationHeader(): void
    {
        $request = new ServerRequest('GET', '/api/orders');
        $request = $request->withHeader('Authorization', '');
        
        $response = $this->middleware->process($request, $this->mockHandler);
        
        $this->assertEquals(401, $response->getStatusCode());
        
        $body = json_decode((string) $response->getBody(), true);
        $this->assertEquals('Missing Authorization header', $body['error']);
    }

    public function testProcessWithBearerTokenButNoSpace(): void
    {
        $request = new ServerRequest('GET', '/api/orders');
        $request = $request->withHeader('Authorization', 'Bearertoken123');
        
        $response = $this->middleware->process($request, $this->mockHandler);
        
        $this->assertEquals(401, $response->getStatusCode());
        
        $body = json_decode((string) $response->getBody(), true);
        $this->assertEquals('Missing bearer token', $body['error']);
    }

    public function testReturns401WhenAuthorizationHeaderMissing(): void
    {
        $request = new ServerRequest('GET', '/test');
        
        $response = $this->middleware->process($request, $this->mockHandler);
        
        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals('application/json', $response->getHeaderLine('Content-Type'));
        
        $body = json_decode((string)$response->getBody(), true);
        $this->assertEquals('Missing bearer token', $body['error']);
    }

    public function testReturns401WhenAuthorizationHeaderInvalid(): void
    {
        $request = new ServerRequest('GET', '/test', ['Authorization' => 'Basic dGVzdA==']);
        
        $response = $this->middleware->process($request, $this->mockHandler);
        
        $this->assertEquals(401, $response->getStatusCode());
    }

    public function testReturns403WhenPermissionDenied(): void
    {
        $request = new ServerRequest('GET', '/test', ['Authorization' => 'Bearer valid.jwt.token']);
        
        $this->mockEnforcer
            ->expects($this->once())
            ->method('requirePermission')
            ->with('valid.jwt.token', 'Orders.Edit')
            ->willReturn(false);
        
        $response = $this->middleware->process($request, $this->mockHandler);
        
        $this->assertEquals(403, $response->getStatusCode());
        $this->assertEquals('application/json', $response->getHeaderLine('Content-Type'));
        
        $body = json_decode((string)$response->getBody(), true);
        $this->assertEquals('Forbidden', $body['error']);
        $this->assertEquals('Orders.Edit', $body['permission']);
    }

    public function testCallsNextHandlerWhenPermissionGranted(): void
    {
        $request = new ServerRequest('GET', '/test', ['Authorization' => 'Bearer valid.jwt.token']);
        $expectedResponse = new Response(200, [], 'Success');
        
        $this->mockEnforcer
            ->expects($this->once())
            ->method('requirePermission')
            ->with('valid.jwt.token', 'Orders.Edit')
            ->willReturn(true);
        
        $this->mockHandler
            ->expects($this->once())
            ->method('handle')
            ->with($request)
            ->willReturn($expectedResponse);
        
        $response = $this->middleware->process($request, $this->mockHandler);
        
        $this->assertSame($expectedResponse, $response);
    }
}