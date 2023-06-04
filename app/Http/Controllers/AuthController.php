<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use App\Models\User;

class AuthController extends Controller
{

    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login','register','google']]);
    }

    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);
        $credentials = $request->only('email', 'password');
        $token = Auth::attempt($credentials);
        if (!$token) {
            return response()->json([
                'status' => 'error',
                'message' => 'Unauthorized',
            ], 401);
        }

        $user = Auth::user();
        return response()->json([
                'status' => 'success',
                'user' => $user,
                'authorisation' => [
                    'token' => $token,
                    'type' => 'bearer',
                ]
            ]);

    }

    public function register(Request $request){
        $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6',
        ]);

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        $token = Auth::login($user);
        return response()->json([
            'status' => 'success',
            'message' => 'User created successfully',
            'user' => $user,
            'authorisation' => [
                'token' => $token,
                'type' => 'bearer',
            ]
        ]);
    }

    public function logout()
    {
        Auth::logout();
        return response()->json([
            'status' => 'success',
            'message' => 'Successfully logged out',
        ]);
    }

    public function refresh()
    {
        return response()->json([
            'status' => 'success',
            'user' => Auth::user(),
            'authorisation' => [
                'token' => Auth::refresh(),
                'type' => 'bearer',
            ]
        ]);
    }

    public function me()
    {
        return response()->json([
            'status' => 'success',
            'user' => Auth::user()
        ]);
    }

    public function google(Request $request){
        
        $request->validate([
            'credential' => 'required|string',
        ]);

        $google_client = new \Google_Client(['client_id' => '697167343567-53l16s3kutef8slm3qts1ip4cbvsf84u.apps.googleusercontent.com']);
        $payload = $google_client->verifyIdToken($request->credential);

        if (!$payload) {
            return response()->json([
                'status' => 'error',
                'message' => 'Unauthorized. Invalid Google Token.',
            ], 405);
        }

        $user = User::where('email', $payload['email'])->where('password', null)->first();
        if ($user == null) {
            $passAuth = User::where('email', $payload['email'])->first();
            if ($passAuth) {
                return response()->json([
                    'status' => 'error',
                    'message' => 'Unauthorized. Login via email and password.',
                ], 402);
            }
            $user = User::create([
                'name' => $payload['name'],
                'email' => $payload['email'],
                'password' => null,
            ]);
        }

        $token = Auth::login($user);

        return response()->json([
            'status' => 'success',
            'user' => $user,
            'access_token' => $token
        ]);

    }

}
