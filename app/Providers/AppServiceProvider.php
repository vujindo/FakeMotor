<?php

namespace App\Providers;

use App\Services\Auth\CognitoAuthService;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     *
     * @return void
     */
    public function register()
    {
        // AWS Cognito
        $this->app->singleton(CognitoAuthService::class, function ($app) {
            return new CognitoAuthService();
        });
    }

    /**
     * Bootstrap any application services.
     *
     * @return void
     */
    public function boot()
    {
        //
    }
}
