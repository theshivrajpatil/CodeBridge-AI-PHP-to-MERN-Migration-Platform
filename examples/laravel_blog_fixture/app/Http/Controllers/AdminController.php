<?php
namespace App\Http\Controllers;

use App\Models\Post;
use App\Models\User;

class AdminController extends Controller
{
    public function stats()
    {
        return response()->json(['users' => User::count(), 'posts' => Post::count()]);
    }
}
