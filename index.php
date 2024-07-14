<?php
// index.php and views folder are just for example how to use
// required define
define('APP_START', microtime(true));
define('APP_URL', 'http://localhost:8000');
define('APP_DEBUG', 1);

require 'SolidPHP.php';

use SolidPHP\Router;
use SolidPHP\CSRF;
use SolidPHP\JWT;
use SolidPHP\Flash;
use SolidPHP\Route;
use SolidPHP\UrlCryptor;
use SolidPHP\Vite;
use SolidPHP\DBMysql;

$app = new Router();

// db
$db = new DBMysql([
    'host' => 'localhost',
    'username' => 'root',
    'password' => 'root',
    'database' => 'test',
]);
// define table
$db->table('persons', [
    'name' => 's',
    'age' => 'i'
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
        return $res->redirect(Route::is('/login'));
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
    return $res->redirect(Route::is('/login'));
});

$app->get('/person', 'useJwtAuth', function ($req, $res) use ($db, $cryptor) {
    $data = $db->query('SELECT * FROM persons')->fetch_all(MYSQLI_ASSOC);

    $persons = $cryptor->encryptField($data, 'id');

    return $res->view(__DIR__ . '/views/pages/person.php', ['persons' => $persons]);
});

$app->post('/person', function ($req, $res) use ($db) {
    CSRF::verify($req);

    $db->prepare("INSERT INTO persons ({$db->fields('persons')}) VALUES (?, ?)")
        ->bind_param('persons', $req["body"]["name"], $req["body"]["age"])
        ->execute();

    Flash::set('message', 'added!');
    return $res->redirect($req["header"]["HTTP_REFERER"] ?? Route::is('/person'));
});

$app->put('/person/:id', function ($req, $res) use ($db, $cryptor) {
    CSRF::verify($req);

    $db->prepare("UPDATE persons SET {$db->setClause('persons')} WHERE id = ?")
        ->bind_param('sii', $req["body"]["name"], $req["body"]["age"], $cryptor->decrypt($req["params"]["id"]))
        ->execute();

    Flash::set('message', 'updated!');
    return $res->redirect($req["header"]["HTTP_REFERER"] ?? Route::is('/person'));
});

$app->post('/person/:id', function ($req, $res) use ($db, $cryptor) {
    CSRF::verify($req);

    $data = $db->prepare("SELECT * FROM persons WHERE id = ?")
        ->bind_param('i', $cryptor->decrypt($req["params"]["id"]))
        ->execute()
        ->get_result()
        ->fetch_assoc();

    return $res->json($data, 200);
});

$app->delete('/person/:id', function ($req, $res) use ($db, $cryptor) {
    CSRF::verify($req);

    $db->prepare("DELETE FROM persons WHERE id = ?")
        ->bind_param('i', $cryptor->decrypt($req["params"]["id"]))
        ->execute();

    Flash::set('message', 'deleted!');
    return $res->redirect($req["header"]["HTTP_REFERER"] ?? Route::is('/person'));
});

$app->rePath('/.*/', function ($req, $res) {
    return $res->php(__DIR__ . "/views/react.php");
});

$app->error(function (Exception $e, $res) {
    return $res->send('path not found', 404);
});

$app->start();
