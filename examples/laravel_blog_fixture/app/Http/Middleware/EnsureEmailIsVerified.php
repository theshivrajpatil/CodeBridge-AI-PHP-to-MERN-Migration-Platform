<?php
namespace App\Http\Middleware;

use Closure;

class EnsureEmailIsVerified
{
    public function handle($request, Closure $next)
    {
        if ($request->user() && !$request->user()->email_verified_at) {
            return response()->json(['message' => 'Unverified'], 409);
        }
        return $next($request);
    }
}
