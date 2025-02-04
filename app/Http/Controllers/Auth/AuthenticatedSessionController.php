<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\LoginRequest;
use App\Models\User;
use App\Services\Auth\CognitoAuthService;
use App\Providers\RouteServiceProvider;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\View\View;

class AuthenticatedSessionController extends Controller
{
    protected $cognitoAuth;

    public function __construct(CognitoAuthService $cognitoAuth)
    {
        $this->cognitoAuth = $cognitoAuth;
    }

    /**
     * Display the login view.
     */
    public function create(): View
    {
        return view('auth.login');
    }

    /**
     * Handle an incoming authentication request.
     */
    public function store(LoginRequest $request)
    {
        $request->validate([
            'email' => 'required|email',
            'password' => 'required',
        ]);

        $result = $this->cognitoAuth->loginUser($request->email, $request->password);

        if (!$result) {
            return back()->withErrors(['email' => 'Invalid credentials']);
        }

        $userAttributes = $this->cognitoAuth->getUserDetails($result['AccessToken']);
        $user = User::where('cognito_user_id', $userAttributes['sub'])
            ->first();

        if ($user) {
            Auth::login($user);
        }else {
            return back()->withErrors(['email' => 'User Not Found']);
        }

        return redirect()->intended(RouteServiceProvider::HOME);
    }

    /**
     * Destroy an authenticated session.
     */
    public function destroy(Request $request): RedirectResponse
    {
        Auth::guard('web')->logout();

        $request->session()->invalidate();

        $request->session()->regenerateToken();

        return redirect('/');
    }
}
