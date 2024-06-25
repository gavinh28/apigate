<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use App\Models\PaymentRecord;
use Carbon\Carbon;
use Carbon\CarbonPeriod;
use DB;

class UpdateExpiredVA extends Command
{
    protected $signature = 'command:expiredva';
    protected $description = 'Update status of expired payment va';

    public function __construct()
    {
        parent::__construct();
    }

    public function handle()
    {
        $now = Carbon::now();
        $expiredRecords = PaymentRecord::where('expire_date_va', '<', $now)
            ->whereIn('status', ['ACTIVE', 'PAID']) // Add 'PAID' status to the condition
            ->where('status', '=', 'ACTIVE')
            ->get();

        foreach ($expiredRecords as $record) {
            $record->update(['status' => 'EXPIRED']);
        }
    }
}
