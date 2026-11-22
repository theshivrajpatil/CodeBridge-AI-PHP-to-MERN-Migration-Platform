<?php

namespace App\Http\Controllers;

use App\Services\UserService;

class UserController
{
    public function index()
    {
        $service = new UserService();
        return $service->listUsers();
    }
}
