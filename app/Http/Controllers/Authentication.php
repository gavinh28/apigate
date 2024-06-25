<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;
use Illuminate\Http\Request;
use Carbon\Carbon;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use App\Models\Token;
use App\Models\ApiLog;

class Authentication extends Controller
{
    protected $client_key;

    public function __construct()
    {
        $this->client_key = env('CLIENT_KEY');
    }

    public function signData($client_key, $timestamp)
    {
        $stringToSign = $client_key . '|' . $timestamp;
        $privateKeyPath = storage_path('app/PEMFormat.PEM');
        $privateKey = openssl_pkey_get_private(file_get_contents($privateKeyPath));

        if (!$privateKey) {
            die('Failed to load private key');
        }

        $signature = '';
        if (!openssl_sign($stringToSign, $signature, $privateKey, OPENSSL_ALGO_SHA256)) {
            die('Failed to sign data: ' . openssl_error_string());
        }

        openssl_free_key($privateKey);
        return base64_encode($signature);
    }

    public function get_IP_address()
    {
        foreach ([
            'HTTP_CLIENT_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_FORWARDED',
            'HTTP_X_CLUSTER_CLIENT_IP',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED',
            'REMOTE_ADDR'
        ] as $key) {
            if (array_key_exists($key, $_SERVER) === true) {
                foreach (explode(',', $_SERVER[$key]) as $IPaddress) {
                    $IPaddress = trim($IPaddress);

                    if (
                        filter_var(
                            $IPaddress,
                            FILTER_VALIDATE_IP,
                            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
                        ) !== false
                    ) {
                        return $IPaddress;
                    }
                }
            }
        }
        return null;
    }

    public function getBrowser()
    {
        $u_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
        $bname = 'Unknown';
        $platform = 'Unknown';
        $version = "";
        $ub = "Unknown"; // Initialize $ub

        if (preg_match('/linux/i', $u_agent)) {
            $platform = 'linux';
        } elseif (preg_match('/macintosh|mac os x/i', $u_agent)) {
            $platform = 'mac';
        } elseif (preg_match('/windows|win32/i', $u_agent)) {
            $platform = 'windows';
        }

        if (preg_match('/MSIE/i', $u_agent) && !preg_match('/Opera/i', $u_agent)) {
            $bname = 'Internet Explorer';
            $ub = "MSIE";
        } elseif (preg_match('/Firefox/i', $u_agent)) {
            $bname = 'Mozilla Firefox';
            $ub = "Firefox";
        } elseif (preg_match('/OPR/i', $u_agent)) {
            $bname = 'Opera';
            $ub = "Opera";
        } elseif (preg_match('/Chrome/i', $u_agent) && !preg_match('/Edge/i', $u_agent)) {
            $bname = 'Google Chrome';
            $ub = "Chrome";
        } elseif (preg_match('/Safari/i', $u_agent) && !preg_match('/Edge/i', $u_agent)) {
            $bname = 'Apple Safari';
            $ub = "Safari";
        } elseif (preg_match('/Netscape/i', $u_agent)) {
            $bname = 'Netscape';
            $ub = "Netscape";
        } elseif (preg_match('/Edge/i', $u_agent)) {
            $bname = 'Edge';
            $ub = "Edge";
        } elseif (preg_match('/Trident/i', $u_agent)) {
            $bname = 'Internet Explorer';
            $ub = "MSIE";
        }

        $known = ['Version', $ub, 'other'];
        $pattern = '#(?<browser>' . join('|', $known) . ')[/ ]+(?<version>[0-9.|a-zA-Z.]*)#';
        if (!preg_match_all($pattern, $u_agent, $matches)) {
            // no matching number, continue
        }
        $i = count($matches['browser']);
        if ($i != 1) {
            if (isset($matches['version'][0]) && strripos($u_agent, "Version") < strripos($u_agent, $ub)) {
                $version = $matches['version'][0];
            } elseif (isset($matches['version'][1])) {
                $version = $matches['version'][1];
            }
        } elseif (isset($matches['version'][0])) {
            $version = $matches['version'][0];
        }

        if ($version == null || $version == "") {
            $version = "?";
        }

        return [
            'userAgent' => $u_agent,
            'name' => $bname,
            'version' => $version,
            'platform' => $platform,
            'pattern' => $pattern
        ];
    }

    public function getToken(Request $request)
    {
        if (!$request->filled('grantType')) {
            return $this->generateErrorResponse(400, '4007302', 'Invalid Mandatory Field', 'grantType is required');
        }

        $grantType = $request->input('grantType');
        if ($grantType !== 'client_credentials') {
            return $this->generateErrorResponse(400, '4007300', 'Bad Request', 'Unsupported grantType');
        }

        $client_key = $request->header('X-CLIENT-KEY');
        $timestamp = $request->header('X-TIMESTAMP');
        if ($client_key !== $this->client_key) {
            return $this->generateErrorResponse(401, '4017303', 'Unauthorized', 'Invalid Client Key');
        }

        $signature = $this->signData($client_key, $timestamp);
        $validatorSignature = $request->header('X-SIGNATURE');

        if ($validatorSignature !== $signature) {
            return $this->generateErrorResponse(401, '4017304', 'Unauthorized', 'Invalid Signature');
        }

        $privateKeyPath = storage_path('app/PEMFormat.PEM');
        $privateKey = openssl_pkey_get_private(file_get_contents($privateKeyPath));
        if (!$privateKey) {
            return $this->generateErrorResponse(500, '5007301', 'Internal Server Error', 'Failed to load private key');
        }

        $ip = $this->get_IP_address();
        $expirationTime = Carbon::now()->addMinutes(15)->timestamp;
        $payload = [
            'exp' => $expirationTime,
            'iss' => 'apigw',
            'iat' => Carbon::now()->timestamp,
        ];

        try {
            $token = JWT::encode($payload, $privateKey, 'RS256');
        } catch (\Exception $e) {
            return $this->generateErrorResponse(500, '5007301', 'Internal Server Error', 'Error generating token');
        }

        $ua = $this->getBrowser();
        $yourbrowser = $ua['name'] . " " . $ua['version'] . " on " . $ua['platform'] . " reports: " . $ua['userAgent'];

        $requestData = $request->all();
        $requestHeaders = $request->header();
        $path = $request->path();
        $responseData = [
            'responseCode' => '2007300',
            'responseMessage' => 'Success',
            'accessToken' => $token,
            'tokenType' => 'Bearer',
            'expiresIn' => 900,
        ];

        ApiLog::create([
            'ip_address' => $ip,
            'request_data' => $requestData,
            'response_data' => $responseData,
            'browser' => $yourbrowser,
            'request_header' => $requestHeaders,
            'path' => $path,
        // Add any other headers you want to log
        ]);

        Token::create([
            'token' => $token,
            'created_at' => Carbon::now(),
            'expired_at' => Carbon::createFromTimestamp($expirationTime),
            'ip_addr' => $ip,
            'status' => 'ACTIVE',
        ]);

        $response = [
            'responseCode' => '2007300',
            'responseMessage' => 'Success',
            'accessToken' => $token,
            'tokenType' => 'Bearer',
            'expiresIn' => 900,
        ];
        return response()->json($response);
    }

    private function generateErrorResponse($status, $responseCode, $responseMessage, $description)
    {
        $ip = $this->get_IP_address();
        $responseData = [
            'status' => 'error',
            'response_code' => $responseCode,
            'response_message' => $responseMessage,
            'description' => $description,
        ];

        ApiLog::create([
            'response_data' => $responseData,
            'ip_address' => $ip,
        ]);

        return response()->json($responseData, $status);
    }
}
