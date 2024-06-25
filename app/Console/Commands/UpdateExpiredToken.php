<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use App\Models\Token;
use Carbon\Carbon;
use Carbon\CarbonPeriod;
use DB;

class UpdateExpiredToken extends Command
{
    protected $signature = 'command:expiredtoken';
    protected $description = 'Update status of expired token';

    public function __construct()
    {
        parent::__construct();
    }

    public function handle()
    {
        $now = Carbon::now();
        $expiredToken = Token::where('expired_at', '<', $now) // Add 'PAID' status to the condition
            ->where('status', '=', 'ACTIVE')
            ->get();

        foreach ($expiredToken as $record) {
            $record->delete(); // This deletes each token individually
        }
    }
}
