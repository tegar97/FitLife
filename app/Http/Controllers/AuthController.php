<?php

namespace App\Http\Controllers;

use App\Helpers\ResponseFormatter;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Symfony\Component\HttpFoundation\Response;
use Tymon\JWTAuth\Exceptions\JWTException;
use JWTAuth;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6'
        ]);

        if ($validator->fails()) {
            return ResponseFormatter::error([
            ],    $validator->errors(), 500);
        }

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        $token = auth()->attempt($request->only('email', 'password'));

        if (!$token) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        $data = [
            'access_token' => $token,
            'token_type' => 'Bearer',
            'expires_in' => auth()->factory()->getTTL() * 60,
            'success' => true,
            'user' => $user
        ];

        return ResponseFormatter::success($data,200);
    }

    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|string|email|max:255',
            'password' => 'required|string|min:6',
        ]);

        if ($validator->fails()) {
            return ResponseFormatter::error([
            ],    $validator->errors(), 500);
        }

        $credentials = $request->only('email', 'password');
        $jwt_token = null;



        try {
            if (!$jwt_token = JWTAuth::attempt($credentials)) {
                return ResponseFormatter::error([
                ],    'Invalid Email or Password', 500);
            }
        } catch (JWTException $e) {
            return ResponseFormatter::error([
            ],    'Could not create token', 500);
        }

        $user = auth()->user();

        $data = [
            'access_token' => $jwt_token,
            'token_type' => 'Bearer',
            'expires_in' => auth()->factory()->getTTL() * 60,
            'success' => true,
            'user' => $user
        ];

        return   ResponseFormatter::success($data,200);
    }

    public function me()
    {
        // check if user not login
        if (!auth()->check()) {
            return  ResponseFormatter::error([
            ],    'User not found', 404);
        }
        $user =  auth()->user();


        if (!$user) {
            return ResponseFormatter::error([
            ],    'User not found', 404);
        }

        return  ResponseFormatter::success($user,200);
    }

    public function logout()
    {
        try {
            auth()->logout();
        } catch (\Exception $e) {
            return  ResponseFormatter::error([
            ],    'Failed to logout, please try again', 500);
        }

        return  ResponseFormatter::success([],200);
    }

    public function refresh(Request $request)
    {
        return $this->respondWithToken($this->guard()->refresh());
    }

    public function respondWithToken($token)
    {
        return  ResponseFormatter::success([
            'access_token' => $token,
            'token_type' => 'Bearer',
            'expires_in' => auth()->factory()->getTTL() * 60,
            'success' => true,
        ],200);
    }




    protected function guard()
    {
        return Auth::guard();
    }

}
