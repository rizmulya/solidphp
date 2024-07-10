<?php
// index.php and views folder are just for example how to use
// required define
define('APP_START', microtime(true));
define('APP_URL', 'http://localhost:8000');
define('APP_DEBUG', 1);

require 'SolidPHP.php';

use SolidPHP\Router;
use SolidPHP\Medoo;
use SolidPHP\CSRF;
use SolidPHP\JWT;
use SolidPHP\Flash;
use function SolidPHP\route;
use SolidPHP\UrlCryptor;
use SolidPHP\Vite;

$app = new Router();

$db = new Medoo([
    'type' => 'mysql',
    'host' => 'localhost',
    'database' => 'test',
    'username' => 'root',
    'password' => 'root'
]);

$cryptor = new UrlCryptor('your-key-here-must-be-32-bytes--');
JWT::setSecretKey('12345678');

Vite::set([
    'devServer' => 'http://localhost:5173',
    'manifestPath' => __DIR__ . '/react/dist/.vite/manifest.json',
    'viteConfigPath' => __DIR__ . '/react/vite.config.js',
    'distPath' => '/react/dist/',
]);


/**
 * Middleware
 */
function useJwtAuth($req, $res, $next)
{
    $jwtToken = JWT::getToken();
    $isValid = JWT::verify($jwtToken);

    if (!$isValid) {
        $res->status(401);
        return $res->redirect(route('/login'));
    };

    $next();
}

/**
 * Routes
 */
$app->get('/', function ($req, $res) {
    // return $res->php(__DIR__ . "/views/react.php");
    return $res->view(__DIR__ . '/views/pages/home.php');
});

$app->get('/login', function ($req, $res) {
    return $res->view(__DIR__ . '/views/pages/login.php');
});

$app->post('/login', function ($req, $res) {
    if ($req['body']['username'] == 'admin' && $req['body']['password'] == 'admin') {
        $token = JWT::generate(['id' => 1, 'name' => 'admin'], 2592000); // 30 day in second
        JWT::setCookie($token);

        return $res->json(['status' => 'success', 'token' => $token]);
    }
    return $res->json(['status' => 'failed'], 403);
});

$app->get('/logout', function ($req, $res) {
    JWT::deleteCookie();
    return $res->redirect(route('/login'));
});

$app->get('/person', 'useJwtAuth', function ($req, $res) use ($db, $cryptor) {
    $data = $db->select('persons', '*');

    $persons = $cryptor->encryptField($data, 'id');

    return $res->view(__DIR__ . '/views/pages/person.php', ['persons' => $persons]);
});

$app->post('/person', function ($req, $res) use ($db) {
    CSRF::verify($req);

    $data = [
        'name' => $req["body"]["name"],
        'age' => $req["body"]["age"],
    ];
    $db->insert('persons', $data);

    Flash::set('message', 'added!');
    return $res->redirect($req["header"]["HTTP_REFERER"] ?? route('/person'));
});

$app->put('/person/:id', function ($req, $res) use ($db, $cryptor) {
    CSRF::verify($req);

    $db->update('persons', [
        'name' => $req["body"]["name"],
        'age' => $req["body"]["age"],
    ], [
        'id' => $cryptor->decrypt($req["params"]["id"])
    ]);

    Flash::set('message', 'updated!');
    return $res->redirect($req["header"]["HTTP_REFERER"] ?? route('/person'));
});

$app->post('/person/:id', function ($req, $res) use ($db, $cryptor) {
    CSRF::verify($req);

    $data = $db->get('persons', [
        'id',
        'name',
        'age'
    ], [
        'id' => $cryptor->decrypt($req["params"]["id"])
    ]);

    return $res->json($data, 200);
});

$app->delete('/person/:id', function ($req, $res) use ($db, $cryptor) {
    CSRF::verify($req);

    $db->delete('persons', [
        'id' => $cryptor->decrypt($req["params"]["id"])
    ]);

    Flash::set('message', 'deleted!');
    return $res->redirect($req["header"]["HTTP_REFERER"] ?? route('/person'));
});

$app->rePath('/.*/', function ($req, $res) {
    return $res->php(__DIR__ . "/views/react.php");
});

$app->error(function (Exception $e, $res) {
    return $res->send('path not found', 404);
});

$app->start();
