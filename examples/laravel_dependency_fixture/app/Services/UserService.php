<?php

namespace App\Services;

use App\Models\User;

class UserService
{
    public function listUsers()
    {
        return User::query()->where('active', true)->get();
    }

    public function createUser(array $data)
    {
        return User::create($data);
    }
}
