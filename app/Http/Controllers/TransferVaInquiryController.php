<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\ValidationException;
use Firebase\JWT\JWT;
use Carbon\Carbon;
use Illuminate\Support\Facades\Http;
use Illuminate\Http\Client\PendingRequest;
use Hashids\Hashids;
use Illuminate\Support\Facades\Config;
use App\Models\PaymentRecord;
use App\Models\Token;
use \App\Models\ApiLog;
use Illuminate\Support\Facades\Log;

use Illuminate\Support\Str;
use Illuminate\Http\Request;
class TransferVaInquiryController extends Controller
{
    protected $client_key;


    public function __construct()
    {
        $this->client_key = env('CLIENT_KEY');
        // $this->middleware('jwt.auth');
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

    public function isValidSignature(Request $request)
    {
        $method = $request->getMethod();
        $endpoint = $request->getPathInfo(); // URL after hostname without query parameters
        $token = Str::after($request->header('Token'), 'Bearer ');
        $timestamp = $request->header('X-Timestamp');
        $body = $request->getContent();
        $bodyHash = strtolower(hash('sha256', json_encode(json_decode($body, true), JSON_UNESCAPED_SLASHES)));

        $stringToSign = implode(':', [$method, $endpoint, $bodyHash, $timestamp]); //$method, $endpoint, $token, $bodyHash, $timestamp
        $computedSignature = hash_hmac('sha512', $stringToSign, $this->client_key);

        $receivedSignature = $request->header('X-Signature');

        return hash_equals($computedSignature, $receivedSignature); // Timing attack safe string comparison
    }

    // private function extractBearerToken(Request $request)
    // {
    //     $authorizationHeader = $request->header('Authorization');

    //     if (Str::startsWith($authorizationHeader, 'Bearer ')) {
    //         return Str::substr($authorizationHeader, 7);
    //     }

    //     return null;
    // }
    
    public function inquiry(Request $request)
    {
        $requestData = $request->all(); // Capture request data
        $ip = $this->get_IP_address();
        $path = $request->path();
    
        // Extract the token from the Authorization header
        $token = $request->bearerToken();
    
        // Check if the token comes from the native PHP script
        if (!$token) {
            // If token is not present, try to get it from another header
            $token = $request->header('Token');
        }
    
        if (!$token) {
            $responseData = [
                'ResponseCode' => '4012401',
                'ResponseMessage' => 'Unauthorized',
                'Message' => 'Missing or invalid token',
            ];
    
            // Log all headers including Authorization
            $requestHeaders = $request->headers->all();
            $requestHeaders['Authorization'] = null; // Mask token in logs if needed
    
            ApiLog::create([
                'ip_address' => $ip,
                'request_data' => $requestData,
                'response_data' => $responseData,
                'request_headers' => $requestHeaders,
                'path' => $path,
            ]);
    
            return response()->json($responseData, 401);
        }
    
        // Check if the token exists in the database and its status is active
        $tokenData = Token::where('token', $token)
            ->where('status', 'ACTIVE')
            ->first();
    
        if (!$tokenData) {
            $responseData = [
                'ResponseCode' => '4012402',
                'ResponseMessage' => 'Unauthorized',
                'Message' => 'Token not found or inactive',
            ];
    
            ApiLog::create([
                'ip_address' => $ip,
                'request_data' => $requestData,
                'response_data' => $responseData,
                'request_headers' => $request->headers->all(),
                'path' => $path,
            ]);
    
            return response()->json($responseData, 401);
        }
//         // Return the token in the response
//         return response()->json([
//             'ResponseCode' => '2000000',
//             'ResponseMessage' => 'Success',
//             'Token' => $token
//         ], 200);
//     }
// }
            

    // Validate the X-CLIENT-KEY header
    $client_key = $request->header('X-CLIENT-KEY');
    if ($client_key !== $this->client_key) {
        $responseData = $this->generateErrorResponse(401, '4017303', 'Unauthorized', 'Invalid Client Key');
        ApiLog::create([
            'ip_address' => $ip,
            'request_data' => $requestData,
            'response_data' => $responseData,
            'request_header' => $request->headers->all(),
            'path' => $path,
        ]);
        return response()->json($responseData, 401);
    }

    // Validate the signature
    $signature = $request->header('X-Signature');
    if (!$signature || !$this->isValidSignature($request)) {
        $responseData = [
            'responseCode' => '4017301',
            'responseMessage' => 'Unauthorized',
            'message' => 'Missing or Invalid Signature',
        ];
        ApiLog::create([
            'ip_address' => $ip,
            'request_data' => $requestData,
            'response_data' => $responseData,
            'request_header' => $request->headers->all(),
            'path' => $path,
        ]);
        return response()->json($responseData, 401);
    }

    // Validate X-External-Id
    $xExternalID = $request->header('X_EXTERNAL_ID');
    if (!$xExternalID || empty($xExternalID)) {
        $responseData = $this->getResponse(400, '4092400', 'Invalid Mandatory Field', 'X-External-Id is required');
        ApiLog::create([
            'ip_address' => $ip,
            'request_data' => $requestData,
            'response_data' => $responseData,
            'request_header' => $request->headers->all(),
            'path' => $path,
        ]);
        return response()->json($responseData, 400);
    }

    // Validate the expected headers
    $expectedHeaders = [
        'Content-Type' => 'application/json',
        'X-PARTNER-ID' => 'BMRI',
        'CHANNEL-ID' => '6021',
        // 'Authorization' => 'Bearer ' . $token,
        'X_EXTERNAL_ID' => $xExternalID,
    ];

    // Validate the request headers
    foreach ($expectedHeaders as $headerName => $expectedValue) {
        $receivedValue = $request->header($headerName);
        if (!$receivedValue || $receivedValue !== $expectedValue) {
            $errorMessage = sprintf('Invalid header %s', $headerName);
            $responseData = $this->getResponse(400, '4002402', $errorMessage);
            ApiLog::create([
                'ip_address' => $ip,
                'request_data' => $requestData,
                'response_data' => $responseData,
                'request_header' => $request->headers->all(),
                'path' => $path,
            ]);
            return response()->json($responseData, 400);
        }
    }

    // Validate the request data
    $validator = Validator::make($request->all(), [
        'partnerServiceId' => 'required|string',
        'customerNo' => 'required|string',
        'virtualAccountNo' => 'required|string',
        'channelCode' => 'required|integer',
        'language' => 'required|string',
        'paidAmount.value' => 'required|numeric',
        'paidAmount.currency' => 'required|string',
        'inquiryRequestId' => 'required|string',
    ]);

    if ($validator->fails()) {
        $errors = $validator->errors()->all();
        $responseData = $this->getResponse(400, '4002402', $errors[0] ?? 'Invalid Mandatory Field');
        ApiLog::create([
            'ip_address' => $ip,
            'request_data' => $requestData,
            'response_data' => $responseData,
            'request_header' => $request->headers->all(),
            'path' => $path,
        ]);
        return response()->json($responseData, 400);
    }

    $virtualAccountNo = $request->input('virtualAccountNo');
    $paymentRecord = PaymentRecord::where('virtualAccountNo', $request->input('virtualAccountNo'))
        ->where('partnerServiceId', $request->input('partnerServiceId'))
        ->where('customerNo', $request->input('customerNo'))
        ->first();

    if (!$paymentRecord) {
        $responseData = $this->getResponse(404, '4042401', 'Invalid Bill/Virtual Account not found');
        ApiLog::create([
            'ip_address' => $ip,
            'request_data' => $requestData,
            'response_data' => $responseData,
            'request_header' => $request->headers->all(),
            'path' => $path,
        ]);
        return response()->json($responseData, 404);
    }

    // Check the status of the transaction
    if ($paymentRecord->status == 'PAID') {
        $responseData = $this->getResponse(404, '4042414', 'Bill has been paid');
        ApiLog::create([
            'ip_address' => $ip,
            'request_data' => $requestData,
            'response_data' => $responseData,
            'request_header' => $request->headers->all(),
            'path' => $path,
        ]);
        return response()->json($responseData, 404);
    } elseif ($paymentRecord->status == 'EXPIRED') {
        $responseData = $this->getResponse(404, '4042519', 'Expired Bill');
        ApiLog::create([
            'ip_address' => $ip,
            'request_data' => $requestData,
            'response_data' => $responseData,
            'request_header' => $request->headers->all(),
            'path' => $path,
        ]);
        return response()->json($responseData, 404);
    } else if ($paymentRecord->status == 'SUSPENDED') {
        $responseData = $this->getResponse(404, '4042412', 'Suspended Bill');
        ApiLog::create([
            'ip_address' => $ip,
            'request_data' => $requestData,
            'response_data' => $responseData,
            'request_header' => $request->headers->all(),
            'path' => $path,
        ]);
        return response()->json($responseData, 404);
    } else if ($paymentRecord->status == 'BLOCKED') {
        $responseData = $this->getResponse(404, '4042412', 'Blocked Bill');
        ApiLog::create([
            'ip_address' => $ip,
            'request_data' => $requestData,
            'response_data' => $responseData,
            'request_header' => $request->headers->all(),
            'path' => $path,
        ]);
        return response()->json($responseData, 404);
    }

    // Retrieve virtual account name (bill name) from the payment record
    $virtualAccountName = $paymentRecord->virtualAccountName;
    $partnerServiceId = $paymentRecord->partnerServiceId;
    $customerNo = $paymentRecord->customerNo;
    $paidAmount_value = $paymentRecord->paidAmount_value;
    $paidAmount_currency = $paymentRecord->paidAmount_currency;
    $expire_date_va = $paymentRecord->expire_date_va;
    $billCode = $paymentRecord->billCode;

    // Retrieve data from database
    $totalPaidAmountInDatabase = $paymentRecord->paidAmount_value;

    // Calculate the total paid amount from the request
    $totalPaidAmountInRequest = $request->input('paidAmount.value');

    // Validate the paid amount
    if ($totalPaidAmountInDatabase != $totalPaidAmountInRequest) {
        $responseData = $this->getResponse(400, '4002402', 'Invalid Paid Amount');
        ApiLog::create([
            'ip_address' => $ip,
            'request_data' => $requestData,
            'response_data' => $responseData,
            'request_header' => $request->headers->all(),
            'path' => $path,
        ]);
        return response()->json($responseData, 400);
    }

    $billDetails = [];
    if (strpos($paymentRecord->billCode, ',') === false) {
        // Single bill type
        $billCode = '01';
        $billDetails[] = [
            'billCode' => $billCode,
            'billName' => $virtualAccountName,
            'billAmount' => [
                'value' => $paidAmount_value,
                'currency' => $paidAmount_currency,
            ],
        ];
    } else {
        // Multiple bill type
        $billCodes = explode(',', $paymentRecord->billCode);
        $billNames = array_fill(0, count($billCodes), $virtualAccountName);
        $billAmounts = array_fill(0, count($billCodes), [
            'value' => $paidAmount_value,
            'currency' => $paidAmount_currency,
        ]);

        for ($i = 0; $i < count($billCodes); $i++) {
            $billCode = str_pad(count($billCodes) - $i, 2, '0', STR_PAD_LEFT);
            $billDetails[] = [
                'billCode' => $billCode,
                'billName' => $billNames[$i],
                'billAmount' => $billAmounts[$i],
            ];
        }
    }

    // Retrieve bill name (virtual account name) from the payment record
    $response = [
        'responseCode' => '2002400',
        'responseMessage' => 'Successful',
        'virtualAccountData' => [
            'inquiryStatus' => '00',
            'inquiryReason' => [
                'english' => 'Successful',
                'indonesia' => 'Sukses',
            ],
            'partnerServiceId' => $partnerServiceId,
            'customerNo' => $customerNo,
            'virtualAccountNo' => $virtualAccountNo,
            'virtualAccountName' => $virtualAccountName,
            'inquiryRequestId' => $request->input('inquiryRequestId'),
            'totalAmount' => [
                'value' => $paidAmount_value,
                'currency' => $paidAmount_currency,
            ],
            'feeAmount' => [
                'value' => $paidAmount_value,
                'currency' => $paidAmount_currency,
            ],
            'virtualAccountTrxType' => '01',
            'expiredDate' => $expire_date_va,
            'additionalInfo' => [
                'channel' => 'VIRTUAL_ACCOUNT_BANK_MANDIRI',
                'virtualAccountConfig' => [
                    'reusableStatus' => $request->input('transactionId') == 2, // Set reusableStatus to TRUE if transactionId is 2 (Open Payment), FALSE otherwise
                ],
            ],
            'billDetails' => $billDetails,
        ],
    ];

    if (strpos($paymentRecord->billCode, ',') === false) {
        // Single bill type
        $paymentRecord->billCode = '01';
    } else {
        // Multiple bill type
        $paymentRecord->billCode = implode(',', array_column($billDetails, 'billCode'));
    }
    $paymentRecord->save();

    $paymentRecord->update([
        'inquiryRequestId' => $request->input('inquiryRequestId'),
    ]);

    ApiLog::create([
        'ip_address' => $ip,
        'request_data' => $requestData,
        'response_data' => $response,
        'request_header' => $request->headers->all(),
        'path' => $path,
    ]);

    // Return the response
    return response()->json($response);
}


    private function getResponse(int $httpCode, string $responseCode, string $responseMessage = null)
    {
        $description = $this->getDescription($responseCode);
        $responseMessage = $responseMessage ?: $this->getResponseMessage($responseCode);

        $response = [
            'status' => 'error',
            'message' => $description ?: $responseMessage,
            'responseCode' => $responseCode,
            'description' => $responseMessage,
        ];

        return response()->json($response, $httpCode);
    }

    private function getDescription(string $responseCode)
    {
        $descriptions = [
            '4002402' => 'Transaction cannot be processed because field or value of the field does not exist in request',
            '4002401' => 'Transaction cannot be processed because field or value of the field is in an invalid format',
            '4012400' => 'General unauthorized error',
            '4002400' => 'Bad Request',
            '4012401' => 'Invalid Token (B2B)',
            '4292400' => 'Maximum transaction per minute limit exceeded',
            '4042401' => 'Invalid Bill/Virtual Account not found',
            '4042412' => 'Invalid bill/virtual account not found/blocked/suspended',
            '4042519' => 'Invalid bill/virtual account expired',
            '4042413' => 'Invalid Amount',
            '4042414' => 'Paid Bill',
            '4092400' => 'Duplicate X-EXTERNAL-ID',
            '5002400' => 'Biller side issue/server error',
            '5002401' => 'Internal Server Error',
            '5042400' => 'Timeout',
        ];

        return $descriptions[$responseCode] ?? null;
    }

    private function getResponseMessage(string $responseCode)
    {
        $messages = [
            '2002400' => 'Successful',
            '4002402' => 'Invalid Mandatory Field',
            '4002401' => 'Invalid Field Format',
            '4012400' => 'Unauthorized',
            '4002400' => 'Bad Request',
            '4012401' => 'Invalid Token (B2B)',
            '4292400' => 'Too many request',
            '4042401' => 'Invalid Bill/Virtual Account not found',
            '4042412' => 'Invalid bill/virtual account not found/blocked/suspended',
            '4042519' => 'Invalid bill/virtual account expired',
            '4042413' => 'Amount does not match with the bill',
            '4042414' => 'Paid bill',
            '4092400' => 'Conflict',
            '5002400' => 'General error',
            '5002401' => 'Internal Server Error',
            '5042400' => 'Time out',
        ];

        return $messages[$responseCode] ?? 'Unknown Error';
    }
    private function generateErrorResponse($status, $responseCode, $responseMessage, $description, $invalidFields = [])
    {
        $errorMessage = [
            'status' => 'error',
            'response code' => $responseCode,
            'response message' => $responseMessage,
            'description' => $description,
        ];

        if (!empty($invalidFields)) {
            $errorMessage['Invalid Fields'] = $invalidFields;
        }

        return response()->json($errorMessage, $status);
    }
}