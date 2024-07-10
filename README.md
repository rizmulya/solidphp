# SolidPHP

SolidPHP is the most `lightweight` and `efficient` PHP Framework with only single file.

#### table of content
- [Docs & Features](#docs--features)
    - [1. API Handler](#1-api-handler)
    - [2. Middleware](#2-middleware)
    - [3. JWT Auth](#3-jwt-auth)
    - [4. Database Framework](#4-database-framework)
    - [5. CSRF Protection](#5-csrf-protection)
    - [6. Templating Engine](#6-templating-engine)
    - [7. Flash Message](#7-flash-message)
    - [8. Url Encryption](#8-url-encryption)
    - [9. React Adaptor](#9-react-adaptor)
    - [9. More](#9-more)
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

### 4. Database Framework

```php
use SolidPHP\Medoo;

// init
$database = new Medoo([
    'type' => 'mysql',
    'host' => 'localhost',
    'database' => 'name',
    'username' => 'your_username',
    'password' => 'your_password'
]);
// use
$database->insert('account', [
    'user_name' => 'foo',
    'email' => 'foo@bar.com'
]);

$data = $database->select('account', [
    'user_name',
    'email'
], [
    'user_id' => 50
]);

echo json_encode($data);
```
[read more about database framework](https://github.com/catfan/Medoo)

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

### 11. More
-  `route($path)`, return full APP_URL + the given $path
```php
use function SolidPHP\route;

<form action="<?= route('/person')?>" ></form> // example.com/person
<link rel="stylesheet" href="<?= route('/public/css/style.css') ?>" /> // example.com/public/css/style.css
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
** Read credits docs for more information.

** if you want to try this example, you can migrate using `php migrate`.

about react:
1. development
    - edit react page? `npm run dev`.
    - or using `php -S localhost:8000`, comment `base` variable, define app_debug to 1, but if want to edit react page recomended to using npm.
2. production
    - add `base` variabel at `vite.config.js`, example: `base: '/react/dist'`.
    - `define('APP_DEBUG', 0);` at `index.php`.
    - run `npm run build` every changes made to react.


## Credits

- [PHPRouter by Mohd Rashid (Modified)](https://github.com/mohdrashid/PHPRouter)
- [Medoo by Angel Lai](https://github.com/catfan/Medoo)
