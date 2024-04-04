<?php

namespace App\Http\Controllers;


use GuzzleHttp\Client;

class Authentication extends Controller
{
    protected $client_id = "BMRI-CLIENT-ID";
    protected $client_secret = "BMRI-CLIENT-SECRET";
    protected $base_uri = "http://103.39.72.2:8080/"; // Assuming a base URI
    protected $access_token;
    protected $client;

    public function __construct()
    {
        // Get access token
        $this->access_token = $this->getAccessToken();

        $this->client = new Client([
            'base_uri' => $this->base_uri . '/api/v1/',
            'headers' => [
                'Authorization' => 'Bearer ' . $this->access_token,
            ],
            'verify' => false,
        ]);
    }

    public function getAccessToken()
    {
        $timestamp = date('c'); // ISO 8601 format, assumed requirement
        $client = new Client([
            'headers' => [
                'X-CLIENT-KEY' => $this->client_id,
                'X-Timestamp' => $timestamp,
                'X-SIGNATURE' => $this->generateSignature($this->client_id, $timestamp),
                'Content-Type' => 'application/json',
            ],
            'verify' => false,
        ]);

        $response = $client->request('POST', "{$this->base_uri}access-token/b2b", [
            'form_params' => [
                'grant_type' => "client_credentials",
            ],
        ]);
        $responseBody = json_decode($response->getBody(), true);
        return $responseBody['access_token'];
    }

    public function generateSignature($client_id, $timestamp)
    {
        // Assuming the client_secret is used as the key for HMAC generation
        return hash_hmac('sha256', $client_id . $timestamp, $this->client_secret);
    }
}
