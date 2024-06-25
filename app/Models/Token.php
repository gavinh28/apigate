<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Token extends Model
{

    protected $fillable = [
        'token', 'created_at', 'expired_at', 'ip_addr', 'status'
    ];

    public $timestamps = false;
}
