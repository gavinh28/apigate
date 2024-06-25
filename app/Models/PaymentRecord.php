<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class PaymentRecord extends Model
{
    protected $fillable = [
        'partnerServiceId', 'customerNo', 'virtualAccountNo', 'virtualAccountName', 'trxDateTime', 'channelCode', 'referenceNo', 'hashedSourceAccountNo', 'paidAmount_value', 'paidAmount_currency', 'paymentRequestId', 'paidBills', 'flagAdvise', 'paidAmount', 'create_date_va', 'update_date_va', 'expire_date_va', 'status', 'inquiryRequestId', 'channel', 'trxID', 'EXTERNAL_ID', 'billCode'
    ];

    public $timestamps = false;

    public function scopeUpdate($query, string $partnerServiceId)
    {
        return $query->where('partnerServiceId', $partnerServiceId);
    }

    public function scopeFindBypartnerServiceId($query, $partnerServiceId)
    {
        return $query->where('partnerServiceId', $partnerServiceId);
    }

    // Define any relationships or additional methods as needed
}
