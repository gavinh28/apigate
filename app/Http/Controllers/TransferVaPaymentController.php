<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Validator;
use Illuminate\Http\Request;

class TransferVaPaymentController extends Controller
{
    public function __construct()
    {
        // $this->middleware('auth:api');
    }

    public function payment(Request $request)
    {
        // Validate the request data
        $validator = Validator::make($request->all(), [
            'partnerServiceId' => 'required|string',
            'customerNo' => 'required|string',
            'virtualAccountNo' => 'required|string',
            'virtualAccountName' => 'required|string',
            'trxDateTime' => 'required|string',
            'channelCode' => 'required|integer',
            'referenceNo' => 'required|string',
            'hashedSourceAccountNo' => 'required|string',
            'paidAmount.value' => 'required|numeric',
            'paidAmount.currency' => 'required|string',
            'paymentRequestId' => 'required|string',
            'paidBills' => 'required|string',
            'flagAdvise' => 'required|string',
        ]);

        if ($validator->fails()) {
            $errors = $validator->errors()->all();
            return $this->getResponse(400, '4002402', $errors[0] ?? 'Invalid Mandatory Field');
        }

        // Build the response data
        $response = [
            'responseCode' => '2002500',
            'responseMessage' => 'Successful',
            'virtualAccountData' => [
                'paymentFlagStatus' => '00',
                'paymentFlagReason' => [
                    'english' => 'Successful',
                    'indonesia' => 'Sukses',
                ],
                'partnerServiceId' => $request->input('partnerServiceId'),
                'customerNo' => $request->input('customerNo'),
                'virtualAccountNo' => $request->input('virtualAccountNo'),
                'virtualAccountName' => $request->input('virtualAccountName'),
                'paymentRequestId' => $request->input('paymentRequestId'),
                'paidAmount' => [
                    'value' => $request->input('paidAmount.value'),
                    'currency' => $request->input('paidAmount.currency'),
                ],
                'trxDateTime' => $request->input('trxDateTime'),
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
