<?php

namespace App\Http\Controllers;
///use models
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Auth;
use Validator;
use App\Models\User;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        //validations
        $validator = Validator::make($request->all(), [
        'email' => 'required|email',
        'password' => 'required',
        'confirm_password' => 'required|same:password',
    ]);

    if($validator->fails()){
        return $this->sendError('Error validation', $validator->errors());       
    }

    $input = $request->all();
    $input['password'] = bcrypt($input['password']);
    $user = User::create($input);
    $success['token'] =  $user->createToken('MyAuthApp')->plainTextToken;
   

    return $this->sendResponse($success, 'User created successfully.');
}

      
    public function login(Request $request)
    {
        if(Auth::attempt(['email' => $request->email, 'password' => $request->password])){ 
            $authUser = Auth::user(); 
            $success['token'] =  $authUser->createToken('MyAuthApp')->plainTextToken; 
            
   
            return $this->sendResponse($success, 'User signed in');
        } 
        else{ 
            return $this->sendError('Unauthorised.', ['error'=>'Unauthorised']);
        } 

        }

    public function logout()
    {
        auth()->user()->tokens()->delete();

        return [
            'message' => 'You have successfully logged out and the token was successfully deleted'
        ];
    }
}
