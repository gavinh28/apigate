<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Validator;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use Illuminate\Support\Facades\Log;

use App\Models\PaymentRecord;
use App\Models\Token;
use \App\Models\ApiLog;

use Carbon\Carbon;


class TransferVaPaymentController extends Controller
{
    protected $client_key;
    public function __construct()
    {
        $this->client_key = env('CLIENT_KEY');
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

        $stringToSign = implode(':', [$method, $endpoint, $token, $bodyHash, $timestamp]);
        $computedSignature = hash_hmac('sha512', $stringToSign, $this->client_key);

        $receivedSignature = $request->header('X-Signature');

        return hash_equals($computedSignature, $receivedSignature); // Timing attack safe string comparison
    }


    public function create(Request $request)
{
    $requestData = $request->all(); // Capture request data
    $ip = $this->get_IP_address(); // Capture IP address
    $path = $request->path();
    // Ensure the Authorization header is present and has the correct format
    // Extract the token from the Authorization header
    $token = $request->bearerToken();
    
    // Check if the token comes from the native PHP script
    if (!$token) {
        // If token is not present, try to get it from another header
        $token = $request->header('Token');
        if ($token) {
            $token = str_replace('Bearer ', '', $token); // Extract token value
        }
    }

    if (!$token) {
        $responseData = [
            'ResponseCode' => '4012401',
            'ResponseMessage' => 'Unauthorized',
            'Message' => 'Missing or invalid token',
        ];

        // Log all headers including Authorization
        $requestHeaders = $request->header();
        $requestHeaders['Token'] = null;

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
            'request_header' => $request->headers->all(),
            'path' => $path,
        ]);
        return response()->json($responseData, 401);
    }

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
        'Token' => 'Bearer ' . $token,
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
        'virtualAccountName' => 'required|string',
        'channelCode' => 'required|numeric|in:6021',
        'paidAmount.value' => 'required|numeric',
        'paidAmount.currency' => 'required|string',
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

    $currentDateTime = \Carbon\Carbon::now()->toDateTimeString();

    // Set the expire_date to 1 minute in the future
    $expire_date_va = Carbon::now()->addHours(10)->toIso8601String();

    // Check if the expiration date is the same as the current time
    if ($expire_date_va === $currentDateTime) {
        // If so, update the status to expired
        $expire_date_va = $currentDateTime;
    }

    $existingRecord = PaymentRecord::where('partnerServiceId', $request->input('partnerServiceId'))
        ->where('customerNo', $request->input('customerNo'))
        ->first();

    if ($existingRecord) {
        // If a record already exists, handle it here
        // For example, you can return an error response indicating that the virtual account already exists
        $responseData = $this->getResponse(400, '4002403', 'Virtual account already exists for the provided partnerServiceId and customerNo');
        ApiLog::create([
            'ip_address' => $ip,
            'request_data' => $requestData,
            'response_data' => $responseData,
            'request_header' => $request->headers->all(),
            'path' => $path,
        ]);
        return response()->json($responseData, 400);
    }

    PaymentRecord::create([
        'partnerServiceId' => $request->input('partnerServiceId'),
        'customerNo' => $request->input('customerNo'),
        'virtualAccountNo' => $request->input('partnerServiceId') . $request->input('customerNo'),
        'virtualAccountName' => $request->input('virtualAccountName'),
        'channelCode' => $request->input('channelCode'),
        'paidAmount_value' => $request->input('paidAmount.value'),
        'paidAmount_currency' => $request->input('paidAmount.currency'),
        'trxID' => '2' . date("YmdHis") . substr(gettimeofday()["usec"], 2),
        'create_date_va' => Carbon::now()->toIso8601String(),
        'expire_date_va' => $expire_date_va,
        'channel' => 'VIRTUAL_ACCOUNT_BANK_MANDIRI',
        'status' => 'ACTIVE',
    ]);

    $paymentRecord = PaymentRecord::where('customerNo', $request->input('customerNo'))->first();

    if (!$paymentRecord) {
        $responseData = $this->getResponse(404, '4042402', 'Payment Record Not Found');
        ApiLog::create([
            'ip_address' => $ip,
            'request_data' => $requestData,
            'response_data' => $responseData,
            'request_header' => $request->headers->all(),
            'path' => $path,
        ]);
        return response()->json($responseData, 404);
    }

    // Retrieve data from database
    $partnerServiceId = $paymentRecord->partnerServiceId;
    $customerNo = $paymentRecord->customerNo;
    $virtualAccountNo = $paymentRecord->virtualAccountNo;
    $virtualAccountName = $paymentRecord->virtualAccountName;
    $trxID = $paymentRecord->trxID;
    $paidAmount_value = $paymentRecord->paidAmount_value;
    $paidAmount_currency = $paymentRecord->paidAmount_currency;

    // Build the response data
    $responseData = [
        'responseCode' => '2002500',
        'responseMessage' => 'Successful',
        'virtualAccountData' => [
            'partnerServiceId' => $partnerServiceId,
            'customerNo' => $customerNo,
            'virtualAccountNo' => $virtualAccountNo,
            'virtualAccountName' => $virtualAccountName,
            'trxID' => $trxID,
            'paidAmount' => [
                'value' => $paidAmount_value,
                'currency' => $paidAmount_currency,
            ],
            'virtualAccountTrxType' => '1',
            'expiredDate' => $expire_date_va,
            'additionalInfo' => [
                'channel' => 'VIRTUAL_ACCOUNT_BANK_MANDIRI',
            ],
        ],
    ];

    ApiLog::create([
        'ip_address' => $ip,
        'request_data' => $requestData,
        'response_data' => $responseData,
        'request_header' => $request->headers->all(),
        'path' => $path,
    ]);

    return response()->json($responseData);
}




public function payment(Request $request)
{
    $requestData = $request->all(); // Capture request data
    $ip = $this->get_IP_address(); // Capture IP address
    $path = $request->path();
    // Ensure the Authorization header is present and has the correct format
    // Extract the token from the Authorization header
    $token = $request->bearerToken();
    
    // Check if the token comes from the native PHP script
    if (!$token) {
        // If token is not present, try to get it from another header
        $token = $request->header('Token');
        if ($token) {
            $token = str_replace('Bearer ', '', $token); // Extract token value
        }
    }

    if (!$token) {
        $responseData = [
            'ResponseCode' => '4012401',
            'ResponseMessage' => 'Unauthorized',
            'Message' => 'Missing or invalid token',
        ];

        // Log all headers including Authorization
        $requestHeaders = $request->header();
        $requestHeaders['Token'] = null;

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
            'request_header' => $request->headers->all(),
            'path' => $path,
        ]);
        return response()->json($responseData, 401);
    }

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
        'Token' => 'Bearer ' . $token,
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
        'virtualAccountName' => 'required|string',
        'paidAmount.value' => 'required|numeric',
        'paidAmount.currency' => 'required|string',
        'referenceNo' => 'required|string',
        'hashedSourceAccountNo' => 'required|string',
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
    } elseif ($paymentRecord->status == 'SUSPENDED') {
        $responseData = $this->getResponse(404, '4042412', 'Suspended Bill');
        ApiLog::create([
            'ip_address' => $ip,
            'request_data' => $requestData,
            'response_data' => $responseData,
            'request_header' => $request->headers->all(),
            'path' => $path,
        ]);
        return response()->json($responseData, 404);
    } elseif ($paymentRecord->status == 'BLOCKED') {
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

    // Retrieve data from database
    $partnerServiceId = $paymentRecord->partnerServiceId;
    $customerNo = $paymentRecord->customerNo;
    $virtualAccountNo = $paymentRecord->virtualAccountNo;
    $virtualAccountName = $paymentRecord->virtualAccountName;
    $trxID = $paymentRecord->trxID;

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

    // Build the response data
    $paymentRequestId = '4' . date("YmdHis") . substr(gettimeofday()["usec"], 2);

    $paymentRecord->update([
        'paymentRequestId' => $paymentRequestId,
        'referenceNo' => $request->input('referenceNo'),
        'hashedSourceAccountNo' => $request->input('hashedSourceAccountNo'),
        'trxDateTime' => Carbon::now()->toIso8601String(),
        'status' => 'PAID',
    ]);

    $trxDateTime = $paymentRecord->trxDateTime;
    $responseData = [
        'responseCode' => '2002500',
        'responseMessage' => 'Successful',
        'virtualAccountData' => [
            'partnerServiceId' => $partnerServiceId,
            'customerNo' => $customerNo,
            'virtualAccountNo' => $virtualAccountNo,
            'virtualAccountName' => $virtualAccountName,
            'paymentRequestId' => $paymentRequestId,
            'trxID' => $trxID,
            'trxDateTime' => $trxDateTime,
        ],
    ];

    ApiLog::create([
        'ip_address' => $ip,
        'request_data' => $requestData,
        'response_data' => $responseData,
        'request_header' => $request->headers->all(),
        'path' => $path,
    ]);

    return response()->json($responseData);
}




    public function checkDatabase($id = null)
    {
        if ($id === null) {
            // No specific id provided, return all payment records
            $paymentRecords = PaymentRecord::all();
            return response()->json($paymentRecords);
        }

        // Retrieve the payment record by id
        $paymentRecord = PaymentRecord::find($id);

        if (!$paymentRecord) {
            return response()->json(['error' => 'Payment record not found'], 404);
        }

        // Return the payment record as JSON response
        return response()->json($paymentRecord);
    }

    public function status(Request $request)
    {
        $requestData = $request->all(); // Capture request data
        $ip = $this->get_IP_address(); // Capture IP address
        $path = $request->path();
        // Ensure the Authorization header is present and has the correct format
        // Extract the token from the Authorization header
    $token = $request->bearerToken();
    
    // Check if the token comes from the native PHP script
    if (!$token) {
        // If token is not present, try to get it from another header
        $token = $request->header('Token');
        if ($token) {
            $token = str_replace('Bearer ', '', $token); // Extract token value
        }
    }

    if (!$token) {
        $responseData = [
            'ResponseCode' => '4012401',
            'ResponseMessage' => 'Unauthorized',
            'Message' => 'Missing or invalid token',
        ];

        // Log all headers including Authorization
        $requestHeaders = $request->header();
        $requestHeaders['Token'] = null;

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
            'request_header' => $request->headers->all(),
            'path' => $path,
        ]);
        return response()->json($responseData, 401);
    }

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
        'Token' => 'Bearer ' . $token,
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
            throw new ValidationException($validator, $responseData);
        }
    
        $paymentRecord = PaymentRecord::where('virtualAccountNo', $request->input('virtualAccountNo'))
            ->where('partnerServiceId', $request->input('partnerServiceId'))
            ->where('customerNo', $request->input('customerNo'))
            ->first();
    
        if (!$paymentRecord) {
            $responseData = $this->getResponse(404, '4042601', 'No payment made for particular bill and inquiryRequestId');
            ApiLog::create([
                'ip_address' => $ip,
                'request_data' => $requestData,
                'response_data' => $responseData,
                'request_header' => $request->headers->all(),
                'path' => $path,
            ]);
            return response()->json($responseData, 404);
        }
    
        $paymentFlagStatus = $paymentRecord->status === 'PAID' ? '00' : '06';
        $paymentFlagReason = $paymentFlagStatus === '00' ? [
            "english" => "Success Payment Flag",
        ] : [
            "english" => "rejected by biller, reversal done",
        ];
        $flagAdvise = $paymentRecord->flagAdvise ?? 'N';
    
        // If the status is "PAID", get the paid bills
        $binaryPaidBills = '';
        if ($paymentRecord->status === 'PAID') {
            // Convert the paid bill codes to a binary string
            foreach (str_split($request->paidBills) as $bill) {
                $binaryPaidBills .= decbin((int)$bill);
            }
        }
    
        // Convert the binary string to a hexadecimal string
        $hexadecimalPaidBills = base_convert(str_pad($binaryPaidBills, 32, '0', STR_PAD_LEFT), 2, 16);
    
        // Retrieve data from payment record
        $virtualAccountName = $paymentRecord->virtualAccountName;
        $partnerServiceId = $paymentRecord->partnerServiceId;
        $customerNo = $paymentRecord->customerNo;
        $paidAmount_value = $paymentRecord->paidAmount_value;
        $paidAmount_currency = $paymentRecord->paidAmount_currency;
        $referenceNo = $paymentRecord->referenceNo;
        $paymentRequestId = $paymentRecord->paymentRequestId;
        $trxDateTime = $paymentRecord->trxDateTime;
        $hashedSourceAccountNo = $paymentRecord->hashedSourceAccountNo;
        $status = $paymentRecord->status;
        $virtualAccountNo = $paymentRecord->virtualAccountNo;
    
        // Build the response data
        $responseData = [
            'responseCode' => '2002600',
            'responseMessage' => 'Successful',
            'virtualAccountData' => [
                'partnerServiceId' => $partnerServiceId,
                'customerNo' => $customerNo,
                'virtualAccountNo' => $virtualAccountNo,
                'virtualAccountName' => $virtualAccountName,
                'trxDateTime' => $trxDateTime,
                'referenceNo' => $referenceNo,
                'paidAmount' => [
                    'value' => $paidAmount_value,
                    'currency' => $paidAmount_currency,
                ],
                'paymentRequestId' => $paymentRequestId,
                'paidBills' => strtoupper($hexadecimalPaidBills),
                'flagAdvise' => $flagAdvise,
                'paymentFlagStatus' => $paymentFlagStatus,
                'paymentFlagReason' => [
                    "english" => $paymentFlagReason,
                ],
                'additionalInfo' => [
                    'hashedSourceAccountNo' => $hashedSourceAccountNo,
                    'channelCode' => '6021',
                ],
                'status' => $status,
            ],
        ];
    
        $paymentRecord->update(['flagAdvise' => $flagAdvise, 'paidBills' => $hexadecimalPaidBills]);
    
        ApiLog::create([
            'ip_address' => $ip,
            'request_data' => $requestData,
            'response_data' => $responseData,
            'request_header' => $request->headers->all(),
            'path' => $path,
        ]);
    
        // Return the response
        return response()->json($responseData);
    }
    


    private function getResponse(int $httpCode, string $responseCode, string $responseMessage = null)
    {
        $description = $this->getDescription($responseCode);
        $responseMessage = $responseMessage ?: $this->getResponseMessage($responseCode);

        $response = [
            'status' => 'error',
            'message' => $description ?: $responseMessage,
            'responseCode' => $responseCode,
            'responseMessage' => $responseMessage,
        ];

        return response()->json($response, $httpCode);
    }

    private function getDescription(string $responseCode)
    {
        $descriptions = [
            '4002402' => 'Transaction cannot be processed because mandatory field does not exist in request',
            '4002401' => 'Transaction cannot be processed because field or value of the field is in an invalid format',
            '4002403' => 'Transaction cannot be processed because the virtual account of the field customer no and partner service id is already used',
            '4042601' => 'Transaction Not Found',
            '4012400' => 'General unauthorized error',
            '4002400' => 'Bad Request',
            '4012401' => 'Invalid Token (B2B)',
            '4292400' => 'Maximum transaction per minute limit exceeded',
            '4042401' => 'Invalid Bill/Virtual Account not found',
            '4042412' => 'Invalid bill/virtual account not found/blocked/suspended',
            '4042519' => 'Invalid bill/virtual account expired',
            '4042413' => 'Amount does not match with the bill',
            '4042414' => 'Bill already paid',
            '4092400' => 'Duplicate X-EXTERNAL-ID',
            '5002400' => 'Biller side issue/server error',
            '5002401' => 'Internal Server Error',
            '5002600' => 'General error',
            '5042400' => 'Timeout',
            '5042600' => 'Timeout',
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
            '4042413' => 'Invalid amount',
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
            'Description' => $description,
        ];

        if (!empty($invalidFields)) {
            $errorMessage['Invalid Fields'] = $invalidFields;
        }

        return response()->json($errorMessage, $status);
    }
}

// public function get_IP_address()
// {
//     foreach (array(
//         'HTTP_CLIENT_IP',
//         'HTTP_X_FORWARDED_FOR',
//         'HTTP_X_FORWARDED',
//         'HTTP_X_CLUSTER_CLIENT_IP',
//         'HTTP_FORWARDED_FOR',
//         'HTTP_FORWARDED',
//         'REMOTE_ADDR'
//     ) as $key) {
//         if (array_key_exists($key, $_SERVER) === true) {
//             foreach (explode(',', $_SERVER[$key]) as $IPaddress) {
//                 $IPaddress = trim($IPaddress); // Just to be safe

//                 if (
//                     filter_var(
//                         $IPaddress,
//                         FILTER_VALIDATE_IP,
//                         FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
//                     )
//                     !== false
//                 ) {
//                     return $IPaddress;
//                 }
//             }
//         }
//     }
//     return null; // Return null if no valid IP address found
// }


    // public function update(Request $request)
    // {
    //     // Ensure the Authorization header is present and has the correct format
    //     $authorizationHeader = $request->header('Authorization');
    //     if (!$authorizationHeader || !Str::startsWith($authorizationHeader, 'Bearer ')) {
    //         return response()->json([
    //             'responseCode' => '4017301',
    //             'responseMessage' => 'Unauthorized',
    //             'message' => 'Missing or invalid Authorization header',
    //         ], 401);
    //     }

    //     // Extract the token from the Authorization header
    //     $token = Str::after($authorizationHeader, 'Bearer ');
    //     if (!$token) {
    //         return response()->json([
    //             'responseCode' => '4012401',
    //             'responseMessage' => 'Unauthorized',
    //             'message' => 'Missing or invalid token',
    //         ], 401);
    //     }

    //     // Validate the X-CLIENT-KEY header
    //     $client_key = $request->header('X-CLIENT-KEY');
    //     if ($client_key !== $this->client_key) {
    //         // Invalid client key
    //         return $this->generateErrorResponse(401, '4017303', 'Unauthorized', 'Invalid Client Key');
    //     }


    //     // Validate the signature
    //     $signature = $request->header('X-Signature');
    //     if (!$signature || !$this->isValidSignature($request)) {
    //         return response()->json([
    //             'responseCode' => '4017301',
    //             'responseMessage' => 'Unauthorized',
    //             'message' => 'Missing or Invalid Signature',
    //         ], 401);
    //     }

    //     //validate X-External-Id
    //     $xExternalID = $request->header('X_EXTERNAL_ID');
    //     if (!$xExternalID || empty($xExternalID)) {
    //         return $this->getResponse(400, '4092400', 'Invalid Mandatory Field', 'X-External-Id is required');
    //     }


    //     // Validate the expected headers
    //     $expectedHeaders = [
    //         'Content-Type' => 'application/json',
    //         'X-PARTNER-ID' => 'BMRI',
    //         'CHANNEL-ID' => '6021',
    //         'Authorization' => 'Bearer ' . $token,
    //         'X_EXTERNAL_ID' => $xExternalID,
    //     ];

    //     // Validate the request headers
    //     foreach ($expectedHeaders as $headerName => $expectedValue) {
    //         $receivedValue = $request->header($headerName);
    //         if (!$receivedValue || $receivedValue !== $expectedValue) {
    //             // Customizing the error message to include the specific header that caused the issue
    //             $errorMessage = sprintf('Invalid header %s', $headerName);
    //             return $this->getResponse(400, '4002402', $errorMessage);
    //         }
    //     }

    //     $validator = Validator::make($request->all(), [
    //         'partnerServiceId' => 'required|string',
    //         'customerNo' => 'required|string',
    //     ]);

    //     if ($validator->fails()) {
    //         $errors = $validator->errors()->all();
    //         return $this->getResponse(400, '4002402', $errors[0] ?? 'Invalid Mandatory Field');
    //     }

    //     $paymentRecord = PaymentRecord::where('customerNo', $request->input('customerNo'))->first();

    //     if (!$paymentRecord) {
    //         return $this->getResponse(404, '4042402', 'Payment Record Not Found');
    //     }

    //     $trxID = $paymentRecord->trxID;
    //     $paidAmountValue = $paymentRecord->paidAmount_value;
    //     $paidAmountCurrency = $paymentRecord->paidAmount_currency;
    //     $status = $paymentRecord->status;
    //     $expire_date_va = $paymentRecord->expire_date_va;

    //     $response = [
    //         'responseCode' => '2002500',
    //         'responseMessage' => 'Successful',
    //         'virtualAccountData' => [
    //             'partnerServiceId' => $request->input('partnerServiceId'),
    //             'customerNo' => $request->input('customerNo'),
    //             'virtualAccountNo' => $request->input('partnerServiceId') . $request->input('customerNo'),
    //             'trxId' => $trxID,
    //             'amount' => [
    //                 'value' => $paidAmountValue,
    //                 'currency' => $paidAmountCurrency,
    //             ],
    //             'virtualAccountTrxType' => '1',
    //             'expiredDate' => $expire_date_va,
    //             'additionalInfo' => [
    //                 'channel' => 'VIRTUAL_ACCOUNT_BANK_MANDIRI',
    //                 'virtualAccountConfig' => [
    //                     'status' => $status,
    //                 ],
    //             ],
    //         ],
    //     ];

    //     $paymentRecord->update([
    //         'partnerServiceId' => $request->input('partnerServiceId'),
    //         'customerNo' => $request->input('customerNo'),
    //         'update_date_va' => Carbon::now()->toIso8601String(),
    //     ]);

    //     return response()->json($response);
    // }


    // public function delete(Request $request)
    // {
    //     // Ensure the Authorization header is present and has the correct format
    //     $authorizationHeader = $request->header('Authorization');
    //     if (!$authorizationHeader || !Str::startsWith($authorizationHeader, 'Bearer ')) {
    //         return response()->json([
    //             'responseCode' => '4017301',
    //             'responseMessage' => 'Unauthorized',
    //             'message' => 'Missing or invalid Authorization header',
    //         ], 401);
    //     }

    //     // Extract the token from the Authorization header
    //     $token = Str::after($authorizationHeader, 'Bearer ');
    //     if (!$token) {
    //         return response()->json([
    //             'responseCode' => '4012401',
    //             'responseMessage' => 'Unauthorized',
    //             'message' => 'Missing or invalid token',
    //         ], 401);
    //     }

    //     // Validate the X-CLIENT-KEY header
    //     $client_key = $request->header('X-CLIENT-KEY');
    //     if ($client_key !== $this->client_key) {
    //         // Invalid client key
    //         return $this->generateErrorResponse(401, '4017303', 'Unauthorized', 'Invalid Client Key');
    //     }


    //     // Validate the signature
    //     $signature = $request->header('X-Signature');
    //     if (!$signature || !$this->isValidSignature($request)) {
    //         return response()->json([
    //             'responseCode' => '4017301',
    //             'responseMessage' => 'Unauthorized',
    //             'message' => 'Missing or Invalid Signature',
    //         ], 401);
    //     }

    //     //validate X-External-Id
    //     $xExternalID = $request->header('X_EXTERNAL_ID');
    //     if (!$xExternalID || empty($xExternalID)) {
    //         return $this->getResponse(400, '4092400', 'Invalid Mandatory Field', 'X-External-Id is required');
    //     }


    //     // Validate the expected headers
    //     $expectedHeaders = [
    //         'Content-Type' => 'application/json',
    //         'X-PARTNER-ID' => 'BMRI',
    //         'CHANNEL-ID' => '6021',
    //         'Authorization' => 'Bearer ' . $token,
    //         'X_EXTERNAL_ID' => $xExternalID,
    //     ];

    //     // Validate the request headers
    //     foreach ($expectedHeaders as $headerName => $expectedValue) {
    //         $receivedValue = $request->header($headerName);
    //         if (!$receivedValue || $receivedValue !== $expectedValue) {
    //             // Customizing the error message to include the specific header that caused the issue
    //             $errorMessage = sprintf('Invalid header %s', $headerName);
    //             return $this->getResponse(400, '4002402', $errorMessage);
    //         }
    //     }
    //     // Validate the request data
    //     $validator = Validator::make($request->all(), [
    //         'partnerServiceId' => 'required|string',
    //         'customerNo' => 'required|string',
    //         'virtualAccountNo' => 'required|string',
    //     ]);

    //     if ($validator->fails()) {
    //         $errors = $validator->errors()->all();
    //         return $this->getResponse(400, '4002402', $errors[0] ?? 'Invalid Mandatory Field');
    //     }

    //     // Extract parameters from request
    //     $partnerServiceId = $request->input('partnerServiceId');
    //     $customerNo = $request->input('customerNo');
    //     $virtualAccountNo = $request->input('virtualAccountNo');

    //     // Find the payment record based on provided parameters
    //     $paymentRecord = PaymentRecord::where('partnerServiceId', $partnerServiceId)
    //         ->where('customerNo', $customerNo)
    //         ->where('virtualAccountNo', $virtualAccountNo)
    //         ->first();

    //     if (!$paymentRecord) {
    //         return $this->getResponse(404, '4042401', 'Payment Record not found');
    //     }

    //     // Delete the payment record
    //     $paymentRecord->delete();


    //     $response = [
    //         'responseCode' => '2002500',
    //         'responseMessage' => 'Successful',
    //         'virtualAccountData' => [
    //             'paymentFlagStatus' => '00',
    //             'paymentFlagReason' => [
    //                 'english' => 'Successful',
    //                 'indonesia' => 'Sukses',
    //             ],
    //             'partnerServiceId' => $partnerServiceId,
    //             'customerNo' => $customerNo,
    //             'virtualAccountNo' => $partnerServiceId . $customerNo,
    //             'paymentRequestId' => $paymentRecord->paymentRequestId, // Assuming paymentRequestId is stored in PaymentRecord
    //             'trxDateTime' => Carbon::now()->toIso8601String(),
    //             'additionalInfo' => [
    //                 'channel' => 'VIRTUAL_ACCOUNT_BANK_MANDIRI', // Example channel name
    //                 'virtualAccountConfig' => [
    //                     'status' => 'DELETED', // Indicate that the virtual account is deleted
    //                 ],
    //             ],
    //         ],
    //     ];
    //     // Return success response
    //     return response()->json($response);
    // }
