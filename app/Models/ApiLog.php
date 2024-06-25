<?php
namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class ApiLog extends Model
{
    protected $fillable = [
        'ip_address',
        'request_data',
        'response_data',
        'request_header',
        'path',
    ];

    protected $casts = [
        'request_data' => 'array',
        'response_data' => 'array',
        'request_header' => 'array',
        'path' => 'array',
    ];
}


