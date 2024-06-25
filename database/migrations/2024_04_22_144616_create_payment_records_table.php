<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class CreatePaymentRecordsTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('payment_records', function (Blueprint $table) {
            $table->id();
            $table->string('partnerServiceId');
            $table->string('customerNo');
            $table->string('virtualAccountNo');
            $table->string('virtualAccountName');
            $table->string('trxDateTime');
            $table->integer('channelCode');
            $table->string('referenceNo');
            $table->string('hashedSourceAccountNo');
            $table->decimal('paidAmount_value', 10, 2); // Assuming paidAmount.value is a decimal value
            $table->string('paidAmount_currency');
            $table->string('paymentRequestId');
            $table->string('paidBills');
            $table->string('flagAdvise');
            $table->string('paidAmount');
            $table->string('status');
            $table->string('inquiryRequestId');
            $table->string('channel');
            $table->string('trxID');
            $table->string('billCode');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('payment_records');
    }
}
