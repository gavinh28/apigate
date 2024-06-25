<?php

namespace App\Providers;

use App\Models\User;
use Throwable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;

class CustomUserProvider implements UserProvider
{
    public function retrieveByToken($identifier, $token)
    {
        throw new Throwable('Method not implemented.');
    }

    public function updateRememberToken(Authenticatable $user, $token)
    {
        throw new Throwable('Method not implemented.');
    }
    public function validateCredentials(Authenticatable $user, array $credentials)
    {
        return true;
    }
}
