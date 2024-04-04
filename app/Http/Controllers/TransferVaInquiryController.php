<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\ValidationException;
use Carbon\Carbon;
use Firebase\JWT\JWT;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Http;

class TransferVaInquiryController extends Controller
{
    public function __construct()
    {
        // $this->middleware('auth:api');
    }

    public function inquiry(Request $request)
    {
        try {
            $this->validateToken($request);

            $this->validateRequest($request);

            // Add the necessary headers
            $headers = [
                'Authorization' => 'Bearer ' . $request->bearerToken(),
                'Content-Type' => 'application/json',
                'X-TIMESTAMP' => Carbon::now()->format(DATE_ISO8601),
                'X-PARTNER-ID' => 'BMRI',
                'X-EXTERNAL-ID' => '7532300325114907378',
                'CHANNEL-ID' => '6021',
            ];

            // Make the HTTP request with the provided headers and request body
            $response = Http::withHeaders($headers)->post('your_api_endpoint_here', $request->all());

            // Check the response status code
            if ($response->status() === 200) {
                return $response->json(); // Return the response from the API
            } else {
                throw new \Exception('Failed to get a successful response from the API');
            }
        } catch (ValidationException $e) {
            return $this->getResponse(400, '4002402', $e->validator->errors()->first());
        } catch (\Exception $e) {
            return $this->getResponse(500, '5002400', $e->getMessage());
        }
    }

    private function validateToken(Request $request)
    {
        $token = $request->bearerToken();

        if (!$token) {
            throw new \Exception('Missing token');
        }

        try {
            $options = new \stdClass();
            $options->algorithm = 'HS256';

            $decodedToken = JWT::decode($token, env('CLIENT_SECRET'), $options);

            // Check if the token has expired
            if (isset($decodedToken->exp) && time() > $decodedToken->exp) {
                throw new \Exception('Token has expired');
            }

            // Check if the required fields exist in the token
            if (!isset($decodedToken->client_id)) {
                throw new \Exception('Invalid token: client_id is missing');
            }
        } catch (\Firebase\JWT\ExpiredException $e) {
            throw new \Exception('Token has expired');
        } catch (\Exception $e) {
            throw new \Exception('Invalid token');
        }
    }





    public function validateRequest(Request $request)
    {
        // Validate the request data
        $validator = Validator::make($request->all(), [
            'partnerServiceId' => 'required|string',
            'customerNo' => 'required|string',
            'virtualAccountNo' => 'required|string',
            'trxDateInit' => 'required|string',
            'channelCode' => 'required|integer',
            'language' => 'required|string',
            'amount.value' => 'required|numeric',
            'amount.currency' => 'required|string',
            'inquiryRequestId' => 'required|string',
        ]);

        if ($validator->fails()) {
            $errors = $validator->errors()->all();
            throw new ValidationException($validator, $this->getResponse(400, '4002402', $errors[0] ?? 'Invalid Mandatory Field'));
        }
    }

    private function buildResponse(Request $request)
    {
        // Build the response data
        $response = [
            'responseCode' => '2002400',
            'responseMessage' => 'Successful',
            'virtualAccountData' => [
                'inquiryStatus' => '00',
                'inquiryReason' => [
                    'english' => 'Successful',
                    'indonesia' => 'Sukses',
                ],
                'partnerServiceId' => $request->input('partnerServiceId'),
                'customerNo' => $request->input('customerNo'),
                'virtualAccountNo' => $request->input('virtualAccountNo'),
                'virtualAccountName' => 'ABCD ' . substr($request->input('virtualAccountNo'), -8),
                'inquiryRequestId' => $request->input('inquiryRequestId'),
                'totalAmount' => [
                    'value' => $request->input('amount.value'),
                    'currency' => $request->input('amount.currency'),
                ],
                'feeAmount' => [
                    'value' => '0.00',
                    'currency' => 'IDR',
                ],
                'billDetails' => [
                    [
                        'billCode' => '01',
                        'billName' => 'ABCD ' . substr($request->input('virtualAccountNo'), -8),
                        'billAmount' => [
                            'value' => $request->input('amount.value'),
                            'currency' => 'IDR',
                        ],
                    ],
                ],
                'freeTexts' => [
                    [
                        'english' => 'PAY7666291231234',
                        'indonesia' => 'PAY7666291231234',
                    ],
                    [
                        'english' => '17-01-22 17:30',
                        'indonesia' => '17-01-22 17:30',
                    ],
                    [
                        'english' => '7888-1231-2314-5362',
                        'indonesia' => '7888-1231-2314-5362',
                    ],
                ],
            ],
        ];

        // Return the response
        return $response;
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
            '4002402' => 'Transaction cannot be processed because field or value of the field does not exist in request',
            '4002401' => 'Transaction cannot be processed because field or value of the field is in an invalid format',
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
            '4042413' => 'Invalid amount',
            '4042414' => 'Paid bill',
            '4092400' => 'Conflict',
            '5002400' => 'General error',
            '5002401' => 'Internal Server Error',
            '5042400' => 'Time out',
        ];

        return $messages[$responseCode] ?? 'Unknown Error';
    }
}
