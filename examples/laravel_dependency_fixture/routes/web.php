<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\UserController;

Route::prefix('admin')->middleware('auth')->group(function () {
    Route::get('/users', [UserController::class, 'index']);
});
