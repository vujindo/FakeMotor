<?php

namespace App\Services\Auth;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\Credentials\Credentials;
use Exception;

class CognitoAuthService
{
    protected $client;
    protected $clientId;
    protected $clientSecret;

    public function __construct()
    {
        $this->client = new CognitoIdentityProviderClient([
            'region' => env('AWS_COGNITO_REGION'),
            'version' => 'latest',
            'credentials' => false,
            // 'credentials' => new Credentials(env('AWS_ACCESS_KEY_ID'), env('AWS_SECRET_ACCESS_KEY'))
        ]);

        $this->clientId = env('AWS_COGNITO_APP_CLIENT_ID');
        $this->clientSecret = env('AWS_COGNITO_APP_CLIENT_SECRET');
    }

    public function loginUser($email, $password)
    {
        try {
            $result = $this->client->initiateAuth([
                'AuthFlow' => 'USER_PASSWORD_AUTH',
                'UserPoolId' => env('AWS_COGNITO_USER_POOL_ID'),
                'ClientId' => $this->clientId,
                'AuthParameters' => [
                    'USERNAME' => $email,
                    'PASSWORD' => $password,
                    'SECRET_HASH'  => $this->calculateSecretHash($email),
                ],
            ]);

            return $result['AuthenticationResult']; // Contains AccessToken, IdToken
        } catch (Exception $e) {
            //Log
            return null; // Handle failed login
        }
    }

    public function getUserDetails($accessToken)
    {
        try {
            $result = $this->client->getUser([
                'AccessToken' => $accessToken,
            ]);

            return collect($result['UserAttributes'])->pluck('Value', 'Name'); // Convert to key-value array
        } catch (Exception $e) {
            return null;
        }
    }

    private function calculateSecretHash($username)
    {
        return base64_encode(
            hash_hmac(
                'sha256',
                $username . $this->clientId,
                $this->clientSecret,
                true
            )
        );
    }

}
