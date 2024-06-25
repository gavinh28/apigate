<?php

/** @var \Laravel\Lumen\Routing\Router $router */

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\TransferVaPaymentController;
use App\Http\Controllers\TransferVaInquiryController;
/*
|--------------------------------------------------------------------------
| Application Routes
|--------------------------------------------------------------------------
|
| Here is where you can register all of the routes for an application.
| It is a breeze. Simply tell Lumen the URIs it should respond to
| and give it the Closure to call when that URI is requested.
|
*/




$router->get('/', function () use ($router) {
    //echo "<center> Welcome </center>";
    return $router->app->version();
});

$router->get('/version', function () use ($router) {
    return $router->app->version();
});

Route::group(['prefix' => 'api'], function () use ($router) {
    Route::post('/v1/transfer-va/inquiry', 'TransferVaInquiryController@inquiry');
    Route::post('/v1/transfer-va/payment', 'TransferVaPaymentController@payment');
    Route::post('/v1/transfer-va/payment/status', 'TransferVaPaymentController@status');
    Route::post('/v1/transfer-va/payment/create', 'TransferVaPaymentController@create');
    Route::post('/v1/transfer-va/payment/update', 'TransferVaPaymentController@update');
    Route::post('/v1/transfer-va/payment/delete', 'TransferVaPaymentController@delete');
});

Route::post('/api/v1/access-token/b2b', 'Authentication@getToken');
// $router->group(['middleware' => 'auth'], function () use ($router) {
//     $router->post('/inquiry', 'TransferVaInquiryController@inquiry');
// });
