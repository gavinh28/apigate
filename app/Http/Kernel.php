<?php

namespace App\Http;

// use Symfony\Component\HttpKernel\Exception\HttpException as HttpKernel;
use App\Http\Middleware\JwtAuthenticate;
use App\Http\Middleware\AuthenticateToken;
use Illuminate\Foundation\Http\Kernel as HttpKernel;

class Kernel extends HttpKernel
{
    /**
     * The application's global HTTP middleware stack.
     *
     * These middleware are run during every request to your application.
     *
     * @var array
     */
    protected $middleware = [
        \App\Http\Middleware\Authenticate::class,
    ];

    /**
     * The application's route middleware groups.
     *
     * @var array
     */
    protected $middlewareGroups = [
        'web' => [],

        'api' => [],
    ];

    /**
     * The application's route middleware.
     *
     * These middleware may be assigned to groups or used individually.
     *
     * @var array
     */
    protected $routeMiddleware = [
        'auth.token' => AuthenticateToken::class,
        'jwt.auth' => 'Tymon\JWTAuth\Middleware\GetUserFromToken',
        'jwt.auth' => JwtAuthenticate::class,
        'jwt.refresh' => 'Tymon\JWTAuth\Middleware\RefreshToken',
        'ensurePost' => \App\Http\Middleware\EnsurePostRequest::class,
        // 'get.jwt.token' => \App\Http\Middleware\GetJwtToken::class,
    ];
}
