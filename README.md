# SolidPHP

SolidPHP is the most `lightweight` and `efficient` PHP Micro Framework.

#### table of content
- [Docs & Features](#docs--features)
    - [1. API Handler](#1-api-handler)
    - [2. Middleware](#2-middleware)
    - [3. JWT Auth](#3-jwt-auth)
    - [4. Database Helpers](#4-database-helpers)
    - [5. CSRF Protection](#5-csrf-protection)
    - [6. Templating Engine](#6-templating-engine)
    - [7. Flash Message](#7-flash-message)
    - [8. Url Encryption](#8-url-encryption)
    - [9. React Adaptor](#9-react-adaptor)
    - [10. More](#10-more)
- [How to Use](#how-to-use)
- [Credits](#credits)

## Docs & Features

### 1. API Handler

```php
use SolidPHP\Router;

$app = new Router();

$app->any('/testing', function($request,$response){
  return $response->send("ANY request");
});

$app->get('/user', function($request,$response){
  return $response->json(["id"=>"1","name"=>"John"],200);
});

$app->post('/:name/:id', function ($req, $res) {
    return $res->json(["id" => $req["params"]["id"], "name" => $req["params"]["name"]], 200);
});

$app->put('/', function($request,$response){
  return $response->send("PUT request");
});

$app->patch('/', function($request,$response){
  return $response->send("PATCH request");
});

$app->delete('/', function($request,$response){
  return $response->send("DELETE request");
});

$app->error(function(Exception $e,$response){
  return $response->send('path not found',404);
});

$app->start();
```

### 2. Middleware

```php
// def
function middleware1($req, $res, $next)
{
    $res->send("Middleware 1 executed");
    $next();
}
function middleware2($req, $res, $next)
{
    $res->send("Middleware 2 executed");
    $next();
}
// use
$app->get('/user', 'middleware1', 'middleware2', function($request,$response){
  return $response->json(["id"=>"1","name"=>"John"],200);
});

```

### 3. JWT Auth
```php
use SolidPHP\JWT;

JWT::setSecretKey('12345678');

// middleware
function useJwtAuth($req, $res, $next)
{
    $jwtToken = JWT::getToken();
    $isValid = JWT::verify($jwtToken);
    // ......
}

$app->post('/login', function ($req, $res) {
    // ......
    $token = JWT::generate(['id' => 1, 'name' => 'admin'], 2592000); // day in second
    JWT::setCookie($token);
    return $res->json(['status' => 'success', 'token' => $token])
    // .....
});

// protected page, use middleware
$app->get('/person', 'useJwtAuth', function ($req, $res) use ($db) {
    // .....
});

$app->get('/logout', function ($req, $res) {
    JWT::deleteCookie();
   // ......
});
```

### 4. Database Helpers


```php
/**
 * Perform simplified, secure, original MySQLi database operations with defined fields and data types.
 * 
 * @method mixed query($query) — Original mysqli query()
 * @method mixed prepare($query) — Original mysqli prepare()
 * @method mixed bind_param($tableName, ...$params) — Modied mysqli bind_param()
 * @method mixed execute() — Original mysqli execute()
 * @method mixed close() — Original mysqli $stmt close()
 * @method mixed shutdown() — Original mysqli close() connection
 * @method mixed getStmt() — Original mysqli $stmt
 * @method mixed get_result() — Original mysqli get_result()
 * @method mixed table($tableName, array $fields) — Define the table for efficiency
 * @method string fields($tableName) — Get fields name based on defined table.
 * @method string setClause($tableName) — Generate SET Clause based on defined table.
 */
use SolidPHP\DBMysql;

// init
$db = new DBMysql([
    'host' => 'localhost',
    'username' => 'your_username',
    'password' => 'your_password',
    'database' => 'your_database',
]);

/**
 * Define the table for efficiency and bind_param() purposes.
 * @param string $tableName
 * @param array $fields['field1' => 'type1']
 * - type 'i' is used for an integer (123)
 * - type 'd' is used for a double (3.14)
 * - type 's' is used for a string ('sample')
 * - type 'b' is used for binary data (file_get_content())
 */
$db->table('persons', [
    'name' => 's',
    'age' => 'i'
]);

// use
// ({$db->fields('persons')}) => use defined table fields
// bind_param('persons'       => use defined data type
 $db->prepare("INSERT INTO persons ({$db->fields('persons')}) VALUES (?, ?)")
    ->bind_param('persons', $req["body"]["name"], $req["body"]["age"]) 
    ->execute();

// use
// {$db->setClause('persons')}  => get set clause from defined table fields
// ->bind_param('sii'           => use raw data type
$db->prepare("UPDATE persons SET {$db->setClause('persons')} WHERE id = ?")
    ->bind_param('sii', $req["body"]["name"], $req["body"]["age"], $cryptor->decrypt($req["params"]["id"]))
    ->execute();

```

### 5. CSRF Protection

```html
use SolidPHP\CSRF;

<!-- init -->
<form method="POST">
    <?= CSRF::token() ?>
    <!-- ..... -->
</form>

<!-- OR from ajax request -->
<script>
    // .....
    headers: {
        'Content-Type': 'application/json',
        'X-CSRF-TOKEN': '<?= CSRF::getToken() ?>', // send from header
    },
    body: JSON.stringify({
        _token: '<?= CSRF::getToken() ?>', // OR send from body 
        id
    })
    // .....
</script>

<!-- verify -->
$app->post('/person', function ($req, $res) use ($db) {
    CSRF::verify($req);

    // .....
});
```

### 6. Templating Engine

routes

```php
$app->get('/profile', 'middleware1', function ($req, $res) {
    // param: view page, data
    $res->phpView(__DIR__ . '/views/pages/profile.php', ['name' => 'John']);
});
```

layout.php

```html
<?php
use SolidPHP\Section;
?>

<head>
    <title><?php Section::yield('title'); ?></title>
</head>
<body>
  <main class="content">
    <!-- yield -->
    <?php Section::yield('content'); ?>
  </main>

  <footer>
    <?php Section::yield('footer'); ?>
  </footer>
</body>
```

page profile.php

```html
<?php
use SolidPHP\Section;
?>
<!-- extends -->
<?php Section::extends(__DIR__.'/../layout.php'); ?>

<!-- set -->
<?php Section::set('title', 'Profile'); ?>

<!-- start - end -->
<?php Section::start('content'); ?>
<h1>Profile</h1>
<p>Welcome to the Profile page!</p>
<?php Section::end('content'); ?>

<?php Section::start('footer'); ?>
<p>
  My name is
  <?= $name ?>
</p>
<?php Section::end('footer'); ?>
```

### 7. Flash Message
```php
use SolidPHP\Flash;
// set
Flash::set('message', 'data successfully added!');
// use
<?php if (Flash::has('message')) : ?>
    <div><?= Flash::get('message'); ?></div>
<?php endif; ?>
```

### 8. Url Encryption
```php
use SolidPHP\UrlCryptor;

// init
$cryptor = new UrlCryptor('your-key-here-must-be-32-bytes--');

$app->get('/person', 'useJwtAuth', function ($req, $res) use ($db, $cryptor) {
    $data = $db->select('persons', '*');
    // encrypt
    // return $data with encrypted id, as id will be used in the url
    $persons = $cryptor->encryptField($data, 'id');
    // .....
});

// decrypt
$app->post('/person/:id', function ($req, $res) use ($db, $cryptor) {
    // ...
    $data = $db->get('persons', [
        // ...
    ], [
        // decrypt the given encrypted /:id
        'id' => $cryptor->decrypt($req["params"]["id"])
    ]);
    // ....
});
```

### 9. React adaptor
Redirect php request to React page
```php
// ......
// place at the end of all routes :

$app->rePath('/.*/', function ($req, $res) {
    return $res->php(__DIR__ . "/views/react.php");
});

$app->start();
// end of code
```

Vite adaptor
```php
use SolidPHP\Vite;

Vite::set([
    'devServer' => 'http://localhost:5173',
    'manifestPath' => __DIR__ . '/react/dist/.vite/manifest.json',
    'viteConfigPath' => __DIR__ . '/react/vite.config.js',
    'distPath' => '/react/dist/',
]);
// 
```

auto changes src & href when running `npm run build`, and change code structure using `Vite::header()` and `Vite::footer()`, based on `APP_DEBUG`.
```html
<head>
    // ....
    <title>React App</title>
    <?php Vite::header(); ?>
</head>
<body>
    <div id="root"></div>
    <?php Vite::footer(); ?>
</body>
```

### 10. More
-  `Route` helpers
```php
/**
 * Route Helper
 * 
 * @method string is($param)        Build a full URL from a given parameter.
 * @method string current()         Get the full current URL.
 * @method bool equals($url)        Check if the current URL equals the given parameter.
 * @method bool contains($string)   Check if the current URL contains the given parameter.
 */
use SolidPHP\Route;

<form action="<?= Route::is('/person')?>" ></form> // example.com/person
<link rel="stylesheet" href="<?= Route::is('/public/css/style.css') ?>" /> // example.com/public/css/style.css

// and more .....
```

- `Filter::out()`, xss protection
```php
use SolidPHP\Filter;

<?php foreach ($persons as $person) : ?>
    <tr>
        <td><?= Filter::out($person['id']) ?></td>
        <td><?= Filter::out($person['name']) ?></td>
    // .......
<?php endforeach; ?>
```
- `Debug`, show responseTime
```php
use SolidPHP\Debug;

<body>
    // ....
    <?= Debug::showResponseTime(microtime(true)) ?>
</body>
```


## How to Use

1. Copy `SolidPHP.php` and `.htaccess` to your project.

** See index.php and views folder for example how to use. <br>
** if you want to try this example, you can migrate using `php migrate`.

about react:
1. development
    - `php -S localhost:8000`, comment `base` variable, define app_debug to 1
    - `npm run dev` and visit react page from `localhost:5173` not from `8000`.
2. production
    - add `base` variabel at `vite.config.js`.
    - `define('APP_DEBUG', 0);` at `index.php`.
    - run `npm run build` every changes made to react.


## Credits

- [PHPRouter (Router & Response class) by Mohd Rashid (modified)](https://github.com/mohdrashid/PHPRouter)
- [SolidPHP by rizmulya](https://github.com/rizmulya/solidphp)
