<?php

/**
 * SolidPHP
 * is The Most Lightweight and Efficient PHP Framework
 * https://github.com/rizmulya/solidphp
 */

declare(strict_types=1);

namespace SolidPHP;

use Exception;

/**
 * Encryption for url safety
 */
class UrlCryptor
{
    private $key;
    private $iv;

    public function __construct($key)
    {
        if (strlen($key) < 32) {
            throw new Exception('Key must be at least 32 bytes long');
        }
        $this->key = $key;
        $this->iv = substr($this->key, 16, 32);
    }

    public function encrypt($data)
    {
        $encrypted = openssl_encrypt(strval($data), 'AES-256-CBC', $this->key, 0, $this->iv);
        return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($encrypted));
    }

    public function decrypt($data)
    {
        $data = base64_decode(str_replace(['-', '_'], ['+', '/'], $data));
        return openssl_decrypt($data, 'AES-256-CBC', $this->key, 0, $this->iv);
    }

    /**
     * Encrypt one field of the given array data
     * @return array Encrypted with $this->encrypt()
     */
    public function encryptField(array $data, $column)
    {
        foreach ($data as &$row) {
            $row[$column] = $this->encrypt($row[$column]);
        }
        return $data;
    }
}


/**
 * JWT Token Engine
 */
class JWT
{
    private static $cookieName = 'jwtToken';
    private static $secretKey;
    private static $expiry;

    /**
     * Set JWT Secret Key
     */
    public static function setSecretKey($key)
    {
        self::$secretKey = $key;
    }

    /**
     * Generate the JWT Token
     */
    public static function generate(array $payload, $expiry = 86400) // (60*60*24) * 1 day
    {
        self::$expiry = $expiry;
        if (!self::$secretKey) {
            throw new Exception('Secret key is not set.');
        }

        $header = self::base64UrlEncode(json_encode(['typ' => 'JWT', 'alg' => 'HS256']));
        $issuedAt = time();
        $payload['iat'] = $issuedAt;
        $payload['exp'] = $issuedAt + $expiry;
        $payload = self::base64UrlEncode(json_encode($payload));

        $signature = self::base64UrlEncode(hash_hmac('sha256', "$header.$payload", self::$secretKey, true));
        return "$header.$payload.$signature";
    }

    /**
     *  Decode JWT Token 
     *  @return array User Data
     */
    public static function decode($token)
    {
        $parts = explode('.', $token);

        $payload = json_decode(self::base64UrlDecode($parts[1]), true);
        return ($payload['exp'] > time()) ? $payload : null;
    }

    /**
     * Verify JWT Token
     * @return bool isValid
     */
    public static function verify($token)
    {
        try {
            $parts = explode('.', $token);
        } catch (\Throwable $th) {
            return false;
        }

        if (count($parts) !== 3) {
            return false;
        }

        [$header, $payload, $signature] = $parts;
        $expectedSignature = self::base64UrlEncode(hash_hmac('sha256', "$header.$payload", self::$secretKey, true));
        return hash_equals($signature, $expectedSignature);
    }

    /**
     * Set cookie with the JWT Token
     */
    public static function setCookie($token, $path = '/', $domain = '', $secure = true, $httpOnly = true)
    {
        setcookie(self::$cookieName, $token, time() + self::$expiry, $path, $domain, $secure, $httpOnly);
    }

    /**
     * remove JWT Token cookie
     */
    public static function deleteCookie()
    {
        setcookie(self::$cookieName, '', time() - 1, '/');
    }

    /**
     * Get JWT Token from request header Authorization or Cookie
     */
    public static function getToken(): String
    {
        $headerAuth = getallheaders()['Authorization'] ?? '';
        if (preg_match('/Bearer\s+(\S+)/', $headerAuth, $matches)) {
            return $matches[1];
        }

        return $_COOKIE[self::$cookieName] ?? '';
    }

    private static function base64UrlEncode($input)
    {
        return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($input));
    }

    private static function base64UrlDecode($input)
    {
        return base64_decode(str_replace(['-', '_'], ['+', '/'], $input));
    }
}


/**
 * Filter Engine
 */
class Filter
{
    /**
     * Filter the given $param to agains xss
     */
    public static function out($param)
    {
        return htmlspecialchars(strval($param), ENT_QUOTES, 'UTF-8');
    }
}


/**
 * Debug Engine
 */
class Debug
{
    /**
     * Show the response time in ms
     */
    public static function showResponseTime($endTime)
    {
        if (!defined('APP_START')) {
            define('APP_START', microtime(true));
        }
        return "<script>
            const cornerText = document.createElement('div');
            cornerText.textContent = '" . number_format(($endTime - APP_START) * 1000, 2) . " ms';
            cornerText.style.cssText = 'position: fixed; bottom: 10px; right: 10px; background-color: black; color: white; padding: 10px; border-radius: 5px; font-size: 14px; font-weight: bold; z-index: 10;';
            document.body.appendChild(cornerText);
        </script>";
    }
}


/**
 * Flash Message Engine
 */
class Flash
{
    private static $sessionKey = '_flash_messages';

    private static function startSession()
    {
        if (session_status() == PHP_SESSION_NONE) {
            session_start();
        }
    }

    /**
     * Set the flash message
     */
    public static function set($key, $message)
    {
        self::startSession();
        $_SESSION[self::$sessionKey][$key] = $message;
    }


    /**
     * Get the flash message
     */
    public static function get($key)
    {
        self::startSession();
        if (isset($_SESSION[self::$sessionKey][$key])) {
            $message = $_SESSION[self::$sessionKey][$key];
            unset($_SESSION[self::$sessionKey][$key]);
            return $message;
        }
        return null;
    }


    /**
     * Check has flash message
     * @return bool
     */
    public static function has($key)
    {
        self::startSession();
        return isset($_SESSION[self::$sessionKey][$key]);
    }
}


/**
 * CSRF Token Engine
 */
class CSRF
{
    private static $sessionKey = '_csrf_token';

    private static function startSession()
    {
        if (session_status() == PHP_SESSION_NONE) {
            session_start();
        }
    }

    /**
     * Generate the CSRF Token
     * @return string generated token
     */
    public static function generate()
    {
        self::startSession();
        if (isset($_SESSION[self::$sessionKey])) {
            return $_SESSION[self::$sessionKey];
        }
        $token = bin2hex(random_bytes(16));
        $_SESSION[self::$sessionKey] = $token;
        return $token;
    }

    /**
     * @return string hidden-input CSRF token, and hidden-input the given method
     */
    public static function token($method = null)
    {
        $token = self::generate();
        $input = '<input type="hidden" name="_token" value="' . $token . '" />';
        return $method ? $input . '<input type="hidden" name="_method" value="' . strtoupper($method) . '" />' : $input;
    }

    /**
     * Get the token
     */
    public static function getToken()
    {
        return self::generate();
    }

    /**
     * Verify the token is valid
     */
    public static function verify($req)
    {
        self::startSession();
        $token = $_POST['_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? null;

        if (!$token && $_SERVER['CONTENT_TYPE'] === 'application/json') {
            $input = json_decode($req['raw'], true);
            $token = $input['_token'] ?? null;
        }

        if (!$token || !hash_equals($_SESSION[self::$sessionKey], $token)) {
            http_response_code(403);
            return die('Ups, invalid!');
        }
    }
}


/**
 *  @return string full APP_URL + the given $path
 */
function route(string $path): string
{
    return rtrim(APP_URL, '/') . '/' . ltrim($path, '/');
}


/**
 * PHPRouter (Router & Response class) by Mohd Rashid (modified).
 * GitHub Repository: https://github.com/mohdrashid/PHPRouter
 */
class Router
{
    private $method;
    private $routes = [];
    private $errorFunction;
    private $request = [];
    private $currentPath;
    private $response;
    private $CharsAllowed = '[a-zA-Z0-9\_\-]+';

    public function __construct()
    {
        $this->method = $_SERVER['REQUEST_METHOD'] ?? null;
        $this->request["method"] = $this->method;
        $this->request["header"] = $this->getHTTPHeaders();
        $this->currentPath = $_SERVER['PATH_INFO'] ?? str_replace(parse_url(APP_URL, PHP_URL_PATH), '', $_SERVER["REQUEST_URI"]);
        $this->request["body"] = $_POST ?? [];
        $this->request["raw"] = file_get_contents('php://input');
        $this->request["params"] = $_GET ?? [];
        $this->request["files"] = $_FILES ?? [];
        $this->request["cookies"] = $_COOKIE ?? [];
        $this->response = new Response();
        $this->routes = ['GET' => [], 'POST' => [], 'PUT' => [], 'DELETE' => [], 'PATCH' => [], 'ANY' => []];
        if ($this->method === 'POST' && isset($_POST['_method'])) {
            $this->method = strtoupper($_POST['_method']);
            $this->request["method"] = $this->method;
        }
    }

    private function getHTTPHeaders()
    {
        return array_filter($_SERVER, function ($name) {
            return preg_match('/^HTTP_/', $name) || preg_match('/^PHP_AUTH_/', $name) || preg_match('/^REQUEST_/', $name);
        }, ARRAY_FILTER_USE_KEY);
    }

    private function getRegexRepresentation($path)
    {
        if (preg_match('/[^-:\/_{}()a-zA-Z\d]/', $path)) return false;
        $path = preg_replace('#\(/\)#', '/?', $path);
        $path = preg_replace('/:(' . $this->CharsAllowed . ')/', '(?<$1>' . $this->CharsAllowed . ')', $path);
        $path = preg_replace('/{(' . $this->CharsAllowed . ')}/', '(?<$1>' . $this->CharsAllowed . ')', $path);
        $path = rtrim($path, '/') . '/?';
        return "@^" . $path . "$@D";
    }

    public function get($path, ...$callback)
    {
        $this->routes['GET'][$this->getRegexRepresentation($path)] = $callback;
    }
    public function post($path, ...$callback)
    {
        $this->routes['POST'][$this->getRegexRepresentation($path)] = $callback;
    }
    public function put($path, ...$callback)
    {
        $this->routes['PUT'][$this->getRegexRepresentation($path)] = $callback;
    }
    public function patch($path, ...$callback)
    {
        $this->routes['PATCH'][$this->getRegexRepresentation($path)] = $callback;
    }
    public function delete($path, ...$callback)
    {
        $this->routes['DELETE'][$this->getRegexRepresentation($path)] = $callback;
    }
    public function any($path, ...$callback)
    {
        $this->routes['ANY'][$this->getRegexRepresentation($path)] = $callback;
    }
    public function error($function)
    {
        $this->errorFunction = $function;
    }

    private function getCallback($method)
    {
        if (!isset($this->routes[$method])) return null;
        foreach ($this->routes[$method] as $name => $callbacks) {
            if (preg_match($name, $this->currentPath, $matches) || preg_match($name, $this->currentPath . "/", $matches)) {
                $this->request["params"] = array_intersect_key($matches, array_flip(array_filter(array_keys($matches), 'is_string')));
                return $callbacks;
            }
        }
        return null;
    }

    public function start()
    {
        $callback = $this->getCallback('ANY') ?? $this->getCallback($this->method);
        if ($callback) return $this->runMiddleware($callback);
        if (isset($this->errorFunction)) return ($this->errorFunction)(new Exception("Path not found!", 404), $this->response);
    }

    private function runMiddleware($callbacks)
    {
        $i = 0;
        $next = function () use (&$i, $callbacks, &$next) {
            if ($i < count($callbacks)) {
                $callback = $callbacks[$i++];
                return $callback($this->request, $this->response, $next);
            }
        };
        return $next();
    }
}


class Response
{
    /**
     * Send Plain Text response
     *
     * @param  string $data   Plaintext message to be output
     * @param  int    $status HTTP code (optional)
     * @return bool           Indication if printing was successful
     */
    public function send($data, $status = null)
    {
        if ($status !== null) {
            http_response_code($status);
        }
        return print($data);
    }

    /**
     * Send response as JSON
     *
     * @param  array $data   PHP array to be output in JSON format
     * @param  int   $status HTTP code (optional)
     * @return bool          Indication if printing was successful
     */
    public function json($data, $status = null)
    {
        header('Content-Type: application/json; charset=utf-8');
        if ($status !== null) {
            http_response_code($status);
        }
        return print(json_encode($data));
    }

    /**
     * @return void PHP page with Templating Engine
     */
    public function phpView($page, $data = [])
    {
        Section::render($page, $data);
    }

    /**
     * @return void header location to the given $path
     */
    public function redirect($path)
    {
        return header('Location: ' . $path);
    }

    /**
     * Return HTTP status only
     *
     * @param  int $status HTTP code
     * @return int         Indication if setting status was successful
     */
    public static function status($status)
    {
        if ($status !== null) {
            http_response_code($status);
            return 1;
        }
        return 0;
    }

    /**
     * Send response as HTML
     *
     * @param  string $filepath Path to the HTML file to be sent
     * @param  int    $status   HTTP code (optional)
     * @return bool             Indication if sending the HTML file was successful
     */
    public function html($filepath, $status = null)
    {
        if (!file_exists($filepath)) {
            throw new Exception('HTML file not found: ' . $filepath);
        }

        header('Content-Type: text/html; charset=utf-8');
        if ($status !== null) {
            http_response_code($status);
        }

        readfile($filepath);
        return true;
    }

    // /**
    //  * Send a file as response
    //  *
    //  * @param  string $filepath Path to the file to be sent
    //  * @param  int    $status   HTTP code (optional)
    //  * @return bool             Indication if sending the file was successful
    //  */
    // public function file($filepath, $status = null)
    // {
    //     if (!file_exists($filepath)) {
    //         throw new Exception('File not found: ' . $filepath);
    //     }

    //     $mime_type = mime_content_type($filepath);
    //     header('Content-Type: ' . $mime_type);
    //     header('Content-Disposition: inline; filename="' . basename($filepath) . '"');

    //     if ($status !== null) {
    //         http_response_code($status);
    //     }

    //     readfile($filepath);
    //     return true;
    // }
}


/**
 * Templating Engine
 */
class Section
{
    private static $sections = [];
    private static $currentSection = null;
    private static $layout = null;

    /**
     * Start one section/part of page
     */
    public static function start($name)
    {
        if (isset(self::$sections[$name])) {
            throw new Exception("The '$name' has started.");
        }
        self::$currentSection = $name;
        ob_start();
    }


    /**
     * End one section/part of page
     */
    public static function end($name)
    {
        if (self::$currentSection !== $name) {
            throw new Exception("The '$name' doesn't match the currently active section '" . self::$currentSection . "'.");
        }
        self::$sections[self::$currentSection] = ob_get_clean();
        self::$currentSection = null;
    }

    /**
     * Define the section/part with the given param $content
     */
    public static function set($name, $content)
    {
        self::$sections[$name] = $content;
    }

    /**
     * Yield the given section/part name
     */
    public static function yield($name)
    {
        if (isset(self::$sections[$name])) {
            echo self::$sections[$name];
        } else {
            echo '';
        }
    }

    /**
     * Extends the layout file
     */
    public static function extends($layoutFile)
    {
        self::$layout = $layoutFile;
    }

    /**
     * Render php page with the Templating Engine support
     */
    public static function render($page, $data = [])
    {
        ob_start();
        extract($data);
        include $page;
        ob_get_clean();
        include self::$layout;
    }
}


/**
 * Medoo Database Framework.
 *
 * The Lightweight PHP Database Framework to Accelerate Development.
 *
 * @version 2.1.12
 * @author Angel Lai
 * @package Medoo
 * @copyright Copyright 2024 Medoo Project, Angel Lai.
 * @license https://opensource.org/licenses/MIT
 * @link https://medoo.in
 */

use PDO;
use PDOException;
use PDOStatement;
use InvalidArgumentException;

/**
 * The Medoo raw object.
 */
class Raw
{
    /**
     * The array of mapping data for the raw string.
     *
     * @var array
     */
    public $map;

    /**
     * The raw string.
     *
     * @var string
     */
    public $value;
}

/**
 * @method array select(string $table, array $columns, array $where)
 * @method null select(string $table, array $columns, callable $callback)
 * @method null select(string $table, array $columns, array $where, callable $callback)
 * @method null select(string $table, array $join, array $columns, array $where, callable $callback)
 * @method mixed get(string $table, array|string $columns, array $where)
 * @method bool has(string $table, array $where)
 * @method mixed rand(string $table, array|string $column, array $where)
 * @method int count(string $table, array $where)
 * @method string max(string $table, string $column)
 * @method string min(string $table, string $column)
 * @method string avg(string $table, string $column)
 * @method string sum(string $table, string $column)
 * @method string max(string $table, string $column, array $where)
 * @method string min(string $table, string $column, array $where)
 * @method string avg(string $table, string $column, array $where)
 * @method string sum(string $table, string $column, array $where)
 */
class Medoo
{
    /**
     * The PDO object.
     *
     * @var \PDO
     */
    public $pdo;

    /**
     * The type of database.
     *
     * @var string
     */
    public $type;

    /**
     * Table prefix.
     *
     * @var string
     */
    protected $prefix;

    /**
     * The PDO statement object.
     *
     * @var \PDOStatement
     */
    protected $statement;

    /**
     * The DSN connection string.
     *
     * @var string
     */
    protected $dsn;

    /**
     * The array of logs.
     *
     * @var array
     */
    protected $logs = [];

    /**
     * Determine should log the query or not.
     *
     * @var bool
     */
    protected $logging = false;

    /**
     * Determine is in test mode.
     *
     * @var bool
     */
    protected $testMode = false;

    /**
     * The last query string was generated in test mode.
     *
     * @var string
     */
    public $queryString;

    /**
     * Determine is in debug mode.
     *
     * @var bool
     */
    protected $debugMode = false;

    /**
     * Determine should save debug logging.
     *
     * @var bool
     */
    protected $debugLogging = false;

    /**
     * The array of logs for debugging.
     *
     * @var array
     */
    protected $debugLogs = [];

    /**
     * The unique global id.
     *
     * @var integer
     */
    protected $guid = 0;

    /**
     * The returned id for the insert.
     *
     * @var string
     */
    public $returnId = '';

    /**
     * Error Message.
     *
     * @var string|null
     */
    public $error = null;

    /**
     * The array of error information.
     *
     * @var array|null
     */
    public $errorInfo = null;

    /**
     * Connect the database.
     *
     * ```
     * $database = new Medoo([
     *      // required
     *      'type' => 'mysql',
     *      'database' => 'name',
     *      'host' => 'localhost',
     *      'username' => 'your_username',
     *      'password' => 'your_password',
     *
     *      // [optional]
     *      'charset' => 'utf8mb4',
     *      'port' => 3306,
     *      'prefix' => 'PREFIX_'
     * ]);
     * ```
     *
     * @param array $options Connection options
     * @return Medoo
     * @throws PDOException
     * @link https://medoo.in/api/new
     * @codeCoverageIgnore
     */

    public function __construct(array $options)
    {
        if (isset($options['prefix'])) {
            $this->prefix = $options['prefix'];
        }

        if (isset($options['testMode']) && $options['testMode'] == true) {
            $this->testMode = true;
            return;
        }

        $options['type'] = $options['type'] ?? $options['database_type'];

        if (!isset($options['pdo'])) {
            $options['database'] = $options['database'] ?? $options['database_name'];

            if (!isset($options['socket'])) {
                $options['host'] = $options['host'] ?? $options['server'] ?? false;
            }
        }

        if (isset($options['type'])) {
            $this->type = strtolower($options['type']);

            if ($this->type === 'mariadb') {
                $this->type = 'mysql';
            }
        }

        if (isset($options['logging']) && is_bool($options['logging'])) {
            $this->logging = $options['logging'];
        }

        $option = $options['option'] ?? [];
        $commands = [];

        switch ($this->type) {

            case 'mysql':
                // Make MySQL using standard quoted identifier.
                $commands[] = 'SET SQL_MODE=ANSI_QUOTES';

                break;

            case 'mssql':
                // Keep MSSQL QUOTED_IDENTIFIER is ON for standard quoting.
                $commands[] = 'SET QUOTED_IDENTIFIER ON';

                // Make ANSI_NULLS is ON for NULL value.
                $commands[] = 'SET ANSI_NULLS ON';

                break;
        }

        if (isset($options['pdo'])) {
            if (!$options['pdo'] instanceof PDO) {
                throw new InvalidArgumentException('Invalid PDO object supplied.');
            }

            $this->pdo = $options['pdo'];

            foreach ($commands as $value) {
                $this->pdo->exec($value);
            }

            return;
        }

        if (isset($options['dsn'])) {
            if (is_array($options['dsn']) && isset($options['dsn']['driver'])) {
                $attr = $options['dsn'];
            } else {
                throw new InvalidArgumentException('Invalid DSN option supplied.');
            }
        } else {
            if (
                isset($options['port']) &&
                is_int($options['port'] * 1)
            ) {
                $port = $options['port'];
            }

            $isPort = isset($port);

            switch ($this->type) {

                case 'mysql':
                    $attr = [
                        'driver' => 'mysql',
                        'dbname' => $options['database']
                    ];

                    if (isset($options['socket'])) {
                        $attr['unix_socket'] = $options['socket'];
                    } else {
                        $attr['host'] = $options['host'];

                        if ($isPort) {
                            $attr['port'] = $port;
                        }
                    }

                    break;

                case 'pgsql':
                    $attr = [
                        'driver' => 'pgsql',
                        'host' => $options['host'],
                        'dbname' => $options['database']
                    ];

                    if ($isPort) {
                        $attr['port'] = $port;
                    }

                    break;

                case 'sybase':
                    $attr = [
                        'driver' => 'dblib',
                        'host' => $options['host'],
                        'dbname' => $options['database']
                    ];

                    if ($isPort) {
                        $attr['port'] = $port;
                    }

                    break;

                case 'oracle':
                    $attr = [
                        'driver' => 'oci',
                        'dbname' => $options['host'] ?
                            '//' . $options['host'] . ($isPort ? ':' . $port : ':1521') . '/' . $options['database'] :
                            $options['database']
                    ];

                    if (isset($options['charset'])) {
                        $attr['charset'] = $options['charset'];
                    }

                    break;

                case 'mssql':
                    if (isset($options['driver']) && $options['driver'] === 'dblib') {
                        $attr = [
                            'driver' => 'dblib',
                            'host' => $options['host'] . ($isPort ? ':' . $port : ''),
                            'dbname' => $options['database']
                        ];

                        if (isset($options['appname'])) {
                            $attr['appname'] = $options['appname'];
                        }

                        if (isset($options['charset'])) {
                            $attr['charset'] = $options['charset'];
                        }
                    } else {
                        $attr = [
                            'driver' => 'sqlsrv',
                            'Server' => $options['host'] . ($isPort ? ',' . $port : ''),
                            'Database' => $options['database']
                        ];

                        if (isset($options['appname'])) {
                            $attr['APP'] = $options['appname'];
                        }

                        $config = [
                            'ApplicationIntent',
                            'AttachDBFileName',
                            'Authentication',
                            'ColumnEncryption',
                            'ConnectionPooling',
                            'Encrypt',
                            'Failover_Partner',
                            'KeyStoreAuthentication',
                            'KeyStorePrincipalId',
                            'KeyStoreSecret',
                            'LoginTimeout',
                            'MultipleActiveResultSets',
                            'MultiSubnetFailover',
                            'Scrollable',
                            'TraceFile',
                            'TraceOn',
                            'TransactionIsolation',
                            'TransparentNetworkIPResolution',
                            'TrustServerCertificate',
                            'WSID',
                        ];

                        foreach ($config as $value) {
                            $keyname = strtolower(preg_replace(['/([a-z\d])([A-Z])/', '/([^_])([A-Z][a-z])/'], '$1_$2', $value));

                            if (isset($options[$keyname])) {
                                $attr[$value] = $options[$keyname];
                            }
                        }
                    }

                    break;

                case 'sqlite':
                    $attr = [
                        'driver' => 'sqlite',
                        $options['database']
                    ];

                    break;
            }
        }

        if (!isset($attr)) {
            throw new InvalidArgumentException('Incorrect connection options.');
        }

        $driver = $attr['driver'];

        if (!in_array($driver, PDO::getAvailableDrivers())) {
            throw new InvalidArgumentException("Unsupported PDO driver: {$driver}.");
        }

        unset($attr['driver']);

        $stack = [];

        foreach ($attr as $key => $value) {
            $stack[] = is_int($key) ? $value : $key . '=' . $value;
        }

        $dsn = $driver . ':' . implode(';', $stack);

        if (
            in_array($this->type, ['mysql', 'pgsql', 'sybase', 'mssql']) &&
            isset($options['charset'])
        ) {
            $commands[] = "SET NAMES '{$options['charset']}'" . (
                $this->type === 'mysql' && isset($options['collation']) ?
                " COLLATE '{$options['collation']}'" : ''
            );
        }

        $this->dsn = $dsn;

        try {
            $this->pdo = new PDO(
                $dsn,
                $options['username'] ?? null,
                $options['password'] ?? null,
                $option
            );

            if (isset($options['error'])) {
                $this->pdo->setAttribute(
                    PDO::ATTR_ERRMODE,
                    in_array($options['error'], [
                        PDO::ERRMODE_SILENT,
                        PDO::ERRMODE_WARNING,
                        PDO::ERRMODE_EXCEPTION
                    ]) ?
                        $options['error'] :
                        PDO::ERRMODE_SILENT
                );
            }

            if (isset($options['command']) && is_array($options['command'])) {
                $commands = array_merge($commands, $options['command']);
            }

            foreach ($commands as $value) {
                $this->pdo->exec($value);
            }
        } catch (PDOException $e) {
            throw new PDOException($e->getMessage());
        }
    }

    /**
     * Generate a new map key for the placeholder.
     *
     * @return string
     */
    protected function mapKey(): string
    {
        return ':MeD' . $this->guid++ . '_mK';
    }

    /**
     * Execute customized raw statement.
     *
     * @param string $statement The raw SQL statement.
     * @param array $map The array of input parameters value for prepared statement.
     * @return \PDOStatement|null
     */
    public function query(string $statement, array $map = []): ?PDOStatement
    {
        $raw = $this->raw($statement, $map);
        $statement = $this->buildRaw($raw, $map);

        return $this->exec($statement, $map);
    }

    /**
     * Execute the raw statement.
     *
     * @param string $statement The SQL statement.
     * @param array $map The array of input parameters value for prepared statement.
     * @codeCoverageIgnore
     * @return \PDOStatement|null
     */
    public function exec(string $statement, array $map = [], callable $callback = null): ?PDOStatement
    {
        $this->statement = null;
        $this->errorInfo = null;
        $this->error = null;

        if ($this->testMode) {
            $this->queryString = $this->generate($statement, $map);
            return null;
        }

        if ($this->debugMode) {
            if ($this->debugLogging) {
                $this->debugLogs[] = $this->generate($statement, $map);
                return null;
            }

            echo $this->generate($statement, $map);

            $this->debugMode = false;

            return null;
        }

        if ($this->logging) {
            $this->logs[] = [$statement, $map];
        } else {
            $this->logs = [[$statement, $map]];
        }

        $statement = $this->pdo->prepare($statement);
        $errorInfo = $this->pdo->errorInfo();

        if ($errorInfo[0] !== '00000') {
            $this->errorInfo = $errorInfo;
            $this->error = $errorInfo[2];

            return null;
        }

        foreach ($map as $key => $value) {
            $statement->bindValue($key, $value[0], $value[1]);
        }

        if (is_callable($callback)) {
            $this->pdo->beginTransaction();
            $callback($statement);
            $execute = $statement->execute();
            $this->pdo->commit();
        } else {
            $execute = $statement->execute();
        }

        $errorInfo = $statement->errorInfo();

        if ($errorInfo[0] !== '00000') {
            $this->errorInfo = $errorInfo;
            $this->error = $errorInfo[2];

            return null;
        }

        if ($execute) {
            $this->statement = $statement;
        }

        return $statement;
    }

    /**
     * Generate readable statement.
     *
     * @param string $statement
     * @param array $map
     * @codeCoverageIgnore
     * @return string
     */
    protected function generate(string $statement, array $map): string
    {
        $identifier = [
            'mysql' => '`$1`',
            'mssql' => '[$1]'
        ];

        $statement = preg_replace(
            '/(?!\'[^\s]+\s?)"([\p{L}_][\p{L}\p{N}@$#\-_]*)"(?!\s?[^\s]+\')/u',
            $identifier[$this->type] ?? '"$1"',
            $statement
        );

        foreach ($map as $key => $value) {
            if ($value[1] === PDO::PARAM_STR) {
                $replace = $this->quote("{$value[0]}");
            } elseif ($value[1] === PDO::PARAM_NULL) {
                $replace = 'NULL';
            } elseif ($value[1] === PDO::PARAM_LOB) {
                $replace = '{LOB_DATA}';
            } else {
                $replace = $value[0] . '';
            }

            $statement = str_replace($key, $replace, $statement);
        }

        return $statement;
    }

    /**
     * Build a raw object.
     *
     * @param string $string The raw string.
     * @param array $map The array of mapping data for the raw string.
     * @return Medoo::raw
     */
    public static function raw(string $string, array $map = []): Raw
    {
        $raw = new Raw();

        $raw->map = $map;
        $raw->value = $string;

        return $raw;
    }

    /**
     * Finds whether the object is raw.
     *
     * @param object $object
     * @return bool
     */
    protected function isRaw($object): bool
    {
        return $object instanceof Raw;
    }

    /**
     * Generate the actual query from the raw object.
     *
     * @param mixed $raw
     * @param array $map
     * @return string|null
     */
    protected function buildRaw($raw, array &$map): ?string
    {
        if (!$this->isRaw($raw)) {
            return null;
        }

        $query = preg_replace_callback(
            '/(([`\'])[\<]*?)?((FROM|TABLE|INTO|UPDATE|JOIN|TABLE IF EXISTS)\s*)?\<(([\p{L}_][\p{L}\p{N}@$#\-_]*)(\.[\p{L}_][\p{L}\p{N}@$#\-_]*)?)\>([^,]*?\2)?/',
            function ($matches) {
                if (!empty($matches[2]) && isset($matches[8])) {
                    return $matches[0];
                }

                if (!empty($matches[4])) {
                    return $matches[1] . $matches[4] . ' ' . $this->tableQuote($matches[5]);
                }

                return $matches[1] . $this->columnQuote($matches[5]);
            },
            $raw->value
        );

        $rawMap = $raw->map;

        if (!empty($rawMap)) {
            foreach ($rawMap as $key => $value) {
                $map[$key] = $this->typeMap($value, gettype($value));
            }
        }

        return $query;
    }

    /**
     * Quote a string for use in a query.
     *
     * @param string $string
     * @return string
     */
    public function quote(string $string): string
    {
        if ($this->type === 'mysql') {
            return "'" . preg_replace(['/([\'"])/', '/(\\\\\\\")/'], ["\\\\\${1}", '\\\${1}'], $string) . "'";
        }

        return "'" . preg_replace('/\'/', '\'\'', $string) . "'";
    }

    /**
     * Quote table name for use in a query.
     *
     * @param string $table
     * @return string
     */
    public function tableQuote(string $table): string
    {
        if (preg_match('/^[\p{L}_][\p{L}\p{N}@$#\-_]*$/u', $table)) {
            return '"' . $this->prefix . $table . '"';
        }

        throw new InvalidArgumentException("Incorrect table name: {$table}.");
    }

    /**
     * Quote column name for use in a query.
     *
     * @param string $column
     * @return string
     */
    public function columnQuote(string $column): string
    {
        if (preg_match('/^[\p{L}_][\p{L}\p{N}@$#\-_]*(\.?[\p{L}_][\p{L}\p{N}@$#\-_]*)?$/u', $column)) {
            return strpos($column, '.') !== false ?
                '"' . $this->prefix . str_replace('.', '"."', $column) . '"' :
                '"' . $column . '"';
        }

        throw new InvalidArgumentException("Incorrect column name: {$column}.");
    }

    /**
     * Mapping the type name as PDO data type.
     *
     * @param mixed $value
     * @param string $type
     * @return array
     */
    protected function typeMap($value, string $type): array
    {
        $map = [
            'NULL' => PDO::PARAM_NULL,
            'integer' => PDO::PARAM_INT,
            'double' => PDO::PARAM_STR,
            'boolean' => PDO::PARAM_BOOL,
            'string' => PDO::PARAM_STR,
            'object' => PDO::PARAM_STR,
            'resource' => PDO::PARAM_LOB
        ];

        if ($type === 'boolean') {
            $value = ($value ? '1' : '0');
        } elseif ($type === 'NULL') {
            $value = null;
        }

        return [$value, $map[$type]];
    }

    /**
     * Build the statement part for the column stack.
     *
     * @param array|string $columns
     * @param array $map
     * @param bool $root
     * @param bool $isJoin
     * @return string
     */
    protected function columnPush(&$columns, array &$map, bool $root, bool $isJoin = false): string
    {
        if ($columns === '*') {
            return $columns;
        }

        $stack = [];
        $hasDistinct = false;

        if (is_string($columns)) {
            $columns = [$columns];
        }

        foreach ($columns as $key => $value) {
            $isIntKey = is_int($key);
            $isArrayValue = is_array($value);

            if (!$isIntKey && $isArrayValue && $root && count(array_keys($columns)) === 1) {
                $stack[] = $this->columnQuote($key);
                $stack[] = $this->columnPush($value, $map, false, $isJoin);
            } elseif ($isArrayValue) {
                $stack[] = $this->columnPush($value, $map, false, $isJoin);
            } elseif (!$isIntKey && $raw = $this->buildRaw($value, $map)) {
                preg_match('/(?<column>[\p{L}_][\p{L}\p{N}@$#\-_\.]*)(\s*\[(?<type>(String|Bool|Int|Number))\])?/u', $key, $match);
                $stack[] = "{$raw} AS {$this->columnQuote($match['column'])}";
            } elseif ($isIntKey && is_string($value)) {
                if ($isJoin && strpos($value, '*') !== false) {
                    throw new InvalidArgumentException('Cannot use table.* to select all columns while joining table.');
                }

                preg_match('/(?<column>[\p{L}_][\p{L}\p{N}@$#\-_\.]*)(?:\s*\((?<alias>[\p{L}_][\p{L}\p{N}@$#\-_]*)\))?(?:\s*\[(?<type>(?:String|Bool|Int|Number|Object|JSON))\])?/u', $value, $match);

                $columnString = '';

                if (!empty($match['alias'])) {
                    $columnString = "{$this->columnQuote($match['column'])} AS {$this->columnQuote($match['alias'])}";
                    $columns[$key] = $match['alias'];

                    if (!empty($match['type'])) {
                        $columns[$key] .= ' [' . $match['type'] . ']';
                    }
                } else {
                    $columnString = $this->columnQuote($match['column']);
                }

                if (!$hasDistinct && strpos($value, '@') === 0) {
                    $columnString = 'DISTINCT ' . $columnString;
                    $hasDistinct = true;
                    array_unshift($stack, $columnString);

                    continue;
                }

                $stack[] = $columnString;
            }
        }

        return implode(',', $stack);
    }

    /**
     * Implode the Where conditions.
     *
     * @param array $data
     * @param array $map
     * @param string $conjunctor
     * @return string
     */
    protected function dataImplode(array $data, array &$map, string $conjunctor): string
    {
        $stack = [];

        foreach ($data as $key => $value) {
            $type = gettype($value);

            if (
                $type === 'array' &&
                preg_match("/^(AND|OR)(\s+#.*)?$/", $key, $relationMatch)
            ) {
                $stack[] = '(' . $this->dataImplode($value, $map, ' ' . $relationMatch[1]) . ')';
                continue;
            }

            $mapKey = $this->mapKey();
            $isIndex = is_int($key);

            preg_match(
                '/([\p{L}_][\p{L}\p{N}@$#\-_\.]*)(\[(?<operator>.*)\])?([\p{L}_][\p{L}\p{N}@$#\-_\.]*)?/u',
                $isIndex ? $value : $key,
                $match
            );

            $column = $this->columnQuote($match[1]);
            $operator = $match['operator'] ?? null;

            if ($isIndex && isset($match[4]) && in_array($operator, ['>', '>=', '<', '<=', '=', '!='])) {
                $stack[] = "{$column} {$operator} " . $this->columnQuote($match[4]);
                continue;
            }

            if ($operator && $operator != '=') {
                if (in_array($operator, ['>', '>=', '<', '<='])) {
                    $condition = "{$column} {$operator} ";

                    if (is_numeric($value)) {
                        $condition .= $mapKey;
                        $map[$mapKey] = [$value, is_float($value) ? PDO::PARAM_STR : PDO::PARAM_INT];
                    } elseif ($raw = $this->buildRaw($value, $map)) {
                        $condition .= $raw;
                    } else {
                        $condition .= $mapKey;
                        $map[$mapKey] = [$value, PDO::PARAM_STR];
                    }

                    $stack[] = $condition;
                } elseif ($operator === '!') {
                    switch ($type) {

                        case 'NULL':
                            $stack[] = $column . ' IS NOT NULL';
                            break;

                        case 'array':
                            $values = [];

                            foreach ($value as $index => $item) {
                                if ($raw = $this->buildRaw($item, $map)) {
                                    $values[] = $raw;
                                } else {
                                    $stackKey = $mapKey . $index . '_i';

                                    $values[] = $stackKey;
                                    $map[$stackKey] = $this->typeMap($item, gettype($item));
                                }
                            }

                            $stack[] = $column . ' NOT IN (' . implode(', ', $values) . ')';
                            break;

                        case 'object':
                            if ($raw = $this->buildRaw($value, $map)) {
                                $stack[] = "{$column} != {$raw}";
                            }
                            break;

                        case 'integer':
                        case 'double':
                        case 'boolean':
                        case 'string':
                            $stack[] = "{$column} != {$mapKey}";
                            $map[$mapKey] = $this->typeMap($value, $type);
                            break;
                    }
                } elseif ($operator === '~' || $operator === '!~') {
                    if ($type !== 'array') {
                        $value = [$value];
                    }

                    $connector = ' OR ';
                    $data = array_values($value);

                    if (is_array($data[0])) {
                        if (isset($value['AND']) || isset($value['OR'])) {
                            $connector = ' ' . array_keys($value)[0] . ' ';
                            $value = $data[0];
                        }
                    }

                    $likeClauses = [];

                    foreach ($value as $index => $item) {
                        $likeKey = "{$mapKey}_{$index}_i";
                        $item = strval($item);

                        if (!preg_match('/((?<!\\\)\[.+(?<!\\\)\]|(?<!\\\)[\*\?\!\%#^_]|%.+|.+%)/', $item)) {
                            $item = '%' . $item . '%';
                        }

                        $likeClauses[] = $column . ($operator === '!~' ? ' NOT' : '') . " LIKE {$likeKey}";
                        $map[$likeKey] = [$item, PDO::PARAM_STR];
                    }

                    $stack[] = '(' . implode($connector, $likeClauses) . ')';
                } elseif ($operator === '<>' || $operator === '><') {
                    if ($type === 'array') {
                        if ($operator === '><') {
                            $column .= ' NOT';
                        }

                        if ($this->isRaw($value[0]) && $this->isRaw($value[1])) {
                            $stack[] = "({$column} BETWEEN {$this->buildRaw($value[0],$map)} AND {$this->buildRaw($value[1],$map)})";
                        } else {
                            $stack[] = "({$column} BETWEEN {$mapKey}a AND {$mapKey}b)";
                            $dataType = (is_numeric($value[0]) && is_numeric($value[1])) ? PDO::PARAM_INT : PDO::PARAM_STR;

                            $map[$mapKey . 'a'] = [$value[0], $dataType];
                            $map[$mapKey . 'b'] = [$value[1], $dataType];
                        }
                    }
                } elseif ($operator === 'REGEXP') {
                    $stack[] = "{$column} REGEXP {$mapKey}";
                    $map[$mapKey] = [$value, PDO::PARAM_STR];
                } else {
                    throw new InvalidArgumentException("Invalid operator [{$operator}] for column {$column} supplied.");
                }

                continue;
            }

            switch ($type) {

                case 'NULL':
                    $stack[] = $column . ' IS NULL';
                    break;

                case 'array':
                    $values = [];

                    foreach ($value as $index => $item) {
                        if ($raw = $this->buildRaw($item, $map)) {
                            $values[] = $raw;
                        } else {
                            $stackKey = $mapKey . $index . '_i';

                            $values[] = $stackKey;
                            $map[$stackKey] = $this->typeMap($item, gettype($item));
                        }
                    }

                    $stack[] = $column . ' IN (' . implode(', ', $values) . ')';
                    break;

                case 'object':
                    if ($raw = $this->buildRaw($value, $map)) {
                        $stack[] = "{$column} = {$raw}";
                    }
                    break;

                case 'integer':
                case 'double':
                case 'boolean':
                case 'string':
                    $stack[] = "{$column} = {$mapKey}";
                    $map[$mapKey] = $this->typeMap($value, $type);
                    break;
            }
        }

        return implode($conjunctor . ' ', $stack);
    }

    /**
     * Build the where clause.
     *
     * @param array|null $where
     * @param array $map
     * @return string
     */
    protected function whereClause($where, array &$map): string
    {
        $clause = '';

        if (is_array($where)) {
            $conditions = array_diff_key($where, array_flip(
                ['GROUP', 'ORDER', 'HAVING', 'LIMIT', 'LIKE', 'MATCH']
            ));

            if (!empty($conditions)) {
                $clause = ' WHERE ' . $this->dataImplode($conditions, $map, ' AND');
            }

            if (isset($where['MATCH']) && $this->type === 'mysql') {
                $match = $where['MATCH'];

                if (is_array($match) && isset($match['columns'], $match['keyword'])) {
                    $mode = '';

                    $options = [
                        'natural' => 'IN NATURAL LANGUAGE MODE',
                        'natural+query' => 'IN NATURAL LANGUAGE MODE WITH QUERY EXPANSION',
                        'boolean' => 'IN BOOLEAN MODE',
                        'query' => 'WITH QUERY EXPANSION'
                    ];

                    if (isset($match['mode'], $options[$match['mode']])) {
                        $mode = ' ' . $options[$match['mode']];
                    }

                    $columns = implode(', ', array_map([$this, 'columnQuote'], $match['columns']));
                    $mapKey = $this->mapKey();
                    $map[$mapKey] = [$match['keyword'], PDO::PARAM_STR];
                    $clause .= ($clause !== '' ? ' AND ' : ' WHERE') . ' MATCH (' . $columns . ') AGAINST (' . $mapKey . $mode . ')';
                }
            }

            if (isset($where['GROUP'])) {
                $group = $where['GROUP'];

                if (is_array($group)) {
                    $stack = [];

                    foreach ($group as $column => $value) {
                        $stack[] = $this->columnQuote($value);
                    }

                    $clause .= ' GROUP BY ' . implode(',', $stack);
                } elseif ($raw = $this->buildRaw($group, $map)) {
                    $clause .= ' GROUP BY ' . $raw;
                } else {
                    $clause .= ' GROUP BY ' . $this->columnQuote($group);
                }
            }

            if (isset($where['HAVING'])) {
                $having = $where['HAVING'];

                if ($raw = $this->buildRaw($having, $map)) {
                    $clause .= ' HAVING ' . $raw;
                } else {
                    $clause .= ' HAVING ' . $this->dataImplode($having, $map, ' AND');
                }
            }

            if (isset($where['ORDER'])) {
                $order = $where['ORDER'];

                if (is_array($order)) {
                    $stack = [];

                    foreach ($order as $column => $value) {
                        if (is_array($value)) {
                            $valueStack = [];

                            foreach ($value as $item) {
                                $valueStack[] = is_int($item) ? $item : $this->quote($item);
                            }

                            $valueString = implode(',', $valueStack);
                            $stack[] = "FIELD({$this->columnQuote($column)}, {$valueString})";
                        } elseif ($value === 'ASC' || $value === 'DESC') {
                            $stack[] = $this->columnQuote($column) . ' ' . $value;
                        } elseif (is_int($column)) {
                            $stack[] = $this->columnQuote($value);
                        }
                    }

                    $clause .= ' ORDER BY ' . implode(',', $stack);
                } elseif ($raw = $this->buildRaw($order, $map)) {
                    $clause .= ' ORDER BY ' . $raw;
                } else {
                    $clause .= ' ORDER BY ' . $this->columnQuote($order);
                }
            }

            if (isset($where['LIMIT'])) {
                $limit = $where['LIMIT'];

                if (in_array($this->type, ['oracle', 'mssql'])) {
                    if ($this->type === 'mssql' && !isset($where['ORDER'])) {
                        $clause .= ' ORDER BY (SELECT 0)';
                    }

                    if (is_numeric($limit)) {
                        $limit = [0, $limit];
                    }

                    if (
                        is_array($limit) &&
                        is_numeric($limit[0]) &&
                        is_numeric($limit[1])
                    ) {
                        $clause .= " OFFSET {$limit[0]} ROWS FETCH NEXT {$limit[1]} ROWS ONLY";
                    }
                } else {
                    if (is_numeric($limit)) {
                        $clause .= ' LIMIT ' . $limit;
                    } elseif (
                        is_array($limit) &&
                        is_numeric($limit[0]) &&
                        is_numeric($limit[1])
                    ) {
                        $clause .= " LIMIT {$limit[1]} OFFSET {$limit[0]}";
                    }
                }
            }
        } elseif ($raw = $this->buildRaw($where, $map)) {
            $clause .= ' ' . $raw;
        }

        return $clause;
    }

    /**
     * Build statement for the select query.
     *
     * @param string $table
     * @param array $map
     * @param array|string $join
     * @param array|string $columns
     * @param array $where
     * @param string $columnFn
     * @return string
     */
    protected function selectContext(
        string $table,
        array &$map,
        $join,
        &$columns = null,
        $where = null,
        $columnFn = null
    ): string {
        preg_match('/(?<table>[\p{L}_][\p{L}\p{N}@$#\-_]*)\s*\((?<alias>[\p{L}_][\p{L}\p{N}@$#\-_]*)\)/u', $table, $tableMatch);

        if (isset($tableMatch['table'], $tableMatch['alias'])) {
            $table = $this->tableQuote($tableMatch['table']);
            $tableAlias = $this->tableQuote($tableMatch['alias']);
            $tableQuery = "{$table} AS {$tableAlias}";
        } else {
            $table = $this->tableQuote($table);
            $tableQuery = $table;
        }

        $isJoin = $this->isJoin($join);

        if ($isJoin) {
            $tableQuery .= ' ' . $this->buildJoin($tableAlias ?? $table, $join, $map);
        } else {
            if (is_null($columns)) {
                if (
                    !is_null($where) ||
                    (is_array($join) && isset($columnFn))
                ) {
                    $where = $join;
                    $columns = null;
                } else {
                    $where = null;
                    $columns = $join;
                }
            } else {
                $where = $columns;
                $columns = $join;
            }
        }

        if (isset($columnFn)) {
            if ($columnFn === 1) {
                $column = '1';

                if (is_null($where)) {
                    $where = $columns;
                }
            } elseif ($raw = $this->buildRaw($columnFn, $map)) {
                $column = $raw;
            } else {
                if (empty($columns) || $this->isRaw($columns)) {
                    $columns = '*';
                    $where = $join;
                }

                $column = $columnFn . '(' . $this->columnPush($columns, $map, true) . ')';
            }
        } else {
            $column = $this->columnPush($columns, $map, true, $isJoin);
        }

        return 'SELECT ' . $column . ' FROM ' . $tableQuery . $this->whereClause($where, $map);
    }

    /**
     * Determine the array with join syntax.
     *
     * @param mixed $join
     * @return bool
     */
    protected function isJoin($join): bool
    {
        if (!is_array($join)) {
            return false;
        }

        $keys = array_keys($join);

        if (
            isset($keys[0]) &&
            is_string($keys[0]) &&
            strpos($keys[0], '[') === 0
        ) {
            return true;
        }

        return false;
    }

    /**
     * Build the join statement.
     *
     * @param string $table
     * @param array $join
     * @param array $map
     * @return string
     */
    protected function buildJoin(string $table, array $join, array &$map): string
    {
        $tableJoin = [];
        $type = [
            '>' => 'LEFT',
            '<' => 'RIGHT',
            '<>' => 'FULL',
            '><' => 'INNER'
        ];

        foreach ($join as $subtable => $relation) {
            preg_match('/(\[(?<join>\<\>?|\>\<?)\])?(?<table>[\p{L}_][\p{L}\p{N}@$#\-_]*)\s?(\((?<alias>[\p{L}_][\p{L}\p{N}@$#\-_]*)\))?/u', $subtable, $match);

            if ($match['join'] === '' || $match['table'] === '') {
                continue;
            }

            if (is_string($relation)) {
                $relation = 'USING ("' . $relation . '")';
            } elseif (is_array($relation)) {
                // For ['column1', 'column2']
                if (isset($relation[0])) {
                    $relation = 'USING ("' . implode('", "', $relation) . '")';
                } else {
                    $joins = [];

                    foreach ($relation as $key => $value) {
                        if ($key === 'AND' && is_array($value)) {
                            $joins[] = $this->dataImplode($value, $map, ' AND');
                            continue;
                        }

                        $joins[] = (
                            strpos($key, '.') > 0 ?
                            // For ['tableB.column' => 'column']
                            $this->columnQuote($key) :

                            // For ['column1' => 'column2']
                            $table . '.' . $this->columnQuote($key)
                        ) .
                            ' = ' .
                            $this->tableQuote($match['alias'] ?? $match['table']) . '.' . $this->columnQuote($value);
                    }

                    $relation = 'ON ' . implode(' AND ', $joins);
                }
            } elseif ($raw = $this->buildRaw($relation, $map)) {
                $relation = $raw;
            }

            $tableName = $this->tableQuote($match['table']);

            if (isset($match['alias'])) {
                $tableName .= ' AS ' . $this->tableQuote($match['alias']);
            }

            $tableJoin[] = $type[$match['join']] . " JOIN {$tableName} {$relation}";
        }

        return implode(' ', $tableJoin);
    }

    /**
     * Mapping columns for the stack.
     *
     * @param array|string $columns
     * @param array $stack
     * @param bool $root
     * @return array
     */
    protected function columnMap($columns, array &$stack, bool $root): array
    {
        if ($columns === '*') {
            return $stack;
        }

        foreach ($columns as $key => $value) {
            if (is_int($key)) {
                preg_match('/([\p{L}_][\p{L}\p{N}@$#\-_]*\.)?(?<column>[\p{L}_][\p{L}\p{N}@$#\-_]*)(?:\s*\((?<alias>[\p{L}_][\p{L}\p{N}@$#\-_]*)\))?(?:\s*\[(?<type>(?:String|Bool|Int|Number|Object|JSON))\])?/u', $value, $keyMatch);

                $columnKey = !empty($keyMatch['alias']) ?
                    $keyMatch['alias'] :
                    $keyMatch['column'];

                $stack[$value] = isset($keyMatch['type']) ?
                    [$columnKey, $keyMatch['type']] :
                    [$columnKey];
            } elseif ($this->isRaw($value)) {
                preg_match('/([\p{L}_][\p{L}\p{N}@$#\-_]*\.)?(?<column>[\p{L}_][\p{L}\p{N}@$#\-_]*)(\s*\[(?<type>(String|Bool|Int|Number))\])?/u', $key, $keyMatch);
                $columnKey = $keyMatch['column'];

                $stack[$key] = isset($keyMatch['type']) ?
                    [$columnKey, $keyMatch['type']] :
                    [$columnKey];
            } elseif (!is_int($key) && is_array($value)) {
                if ($root && count(array_keys($columns)) === 1) {
                    $stack[$key] = [$key, 'String'];
                }

                $this->columnMap($value, $stack, false);
            }
        }

        return $stack;
    }

    /**
     * Mapping the data from the table.
     *
     * @param array $data
     * @param array $columns
     * @param array $columnMap
     * @param array $stack
     * @param bool $root
     * @param array $result
     * @codeCoverageIgnore
     * @return void
     */
    protected function dataMap(
        array $data,
        array $columns,
        array $columnMap,
        array &$stack,
        bool $root,
        array &$result = null
    ): void {
        if ($root) {
            $columnsKey = array_keys($columns);

            if (count($columnsKey) === 1 && is_array($columns[$columnsKey[0]])) {
                $indexKey = array_keys($columns)[0];
                $dataKey = preg_replace("/^[\p{L}_][\p{L}\p{N}@$#\-_]*\./u", '', $indexKey);
                $currentStack = [];

                foreach ($data as $item) {
                    $this->dataMap($data, $columns[$indexKey], $columnMap, $currentStack, false, $result);
                    $index = $data[$dataKey];

                    if (isset($result)) {
                        $result[$index] = $currentStack;
                    } else {
                        $stack[$index] = $currentStack;
                    }
                }
            } else {
                $currentStack = [];
                $this->dataMap($data, $columns, $columnMap, $currentStack, false, $result);

                if (isset($result)) {
                    $result[] = $currentStack;
                } else {
                    $stack = $currentStack;
                }
            }

            return;
        }

        foreach ($columns as $key => $value) {
            $isRaw = $this->isRaw($value);

            if (is_int($key) || $isRaw) {
                $map = $columnMap[$isRaw ? $key : $value];
                $columnKey = $map[0];
                $item = $data[$columnKey];

                if (isset($map[1])) {
                    if ($isRaw && in_array($map[1], ['Object', 'JSON'])) {
                        continue;
                    }

                    if (is_null($item)) {
                        $stack[$columnKey] = null;
                        continue;
                    }

                    switch ($map[1]) {

                        case 'Number':
                            $stack[$columnKey] = (float) $item;
                            break;

                        case 'Int':
                            $stack[$columnKey] = (int) $item;
                            break;

                        case 'Bool':
                            $stack[$columnKey] = (bool) $item;
                            break;

                        case 'Object':
                            $stack[$columnKey] = unserialize($item);
                            break;

                        case 'JSON':
                            $stack[$columnKey] = json_decode($item, true);
                            break;

                        case 'String':
                            $stack[$columnKey] = (string) $item;
                            break;
                    }
                } else {
                    $stack[$columnKey] = $item;
                }
            } else {
                $currentStack = [];
                $this->dataMap($data, $value, $columnMap, $currentStack, false, $result);

                $stack[$key] = $currentStack;
            }
        }
    }

    /**
     * Build and execute returning query.
     *
     * @param string $query
     * @param array $map
     * @param array $data
     * @return \PDOStatement|null
     */
    private function returningQuery($query, &$map, &$data): ?PDOStatement
    {
        $returnColumns = array_map(
            function ($value) {
                return $value[0];
            },
            $data
        );

        $query .= ' RETURNING ' .
            implode(', ', array_map([$this, 'columnQuote'], $returnColumns)) .
            ' INTO ' .
            implode(', ', array_keys($data));

        return $this->exec($query, $map, function ($statement) use (&$data) {
            // @codeCoverageIgnoreStart
            foreach ($data as $key => $return) {
                if (isset($return[3])) {
                    $statement->bindParam($key, $data[$key][1], $return[2], $return[3]);
                } else {
                    $statement->bindParam($key, $data[$key][1], $return[2]);
                }
            }
            // @codeCoverageIgnoreEnd
        });
    }

    /**
     * Create a table.
     *
     * @param string $table
     * @param array $columns Columns definition.
     * @param array $options Additional table options for creating a table.
     * @return \PDOStatement|null
     */
    public function create(string $table, $columns, $options = null): ?PDOStatement
    {
        $stack = [];
        $tableOption = '';
        $tableName = $this->tableQuote($table);

        foreach ($columns as $name => $definition) {
            if (is_int($name)) {
                $stack[] = preg_replace('/\<([\p{L}_][\p{L}\p{N}@$#\-_]*)\>/u', '"$1"', $definition);
            } elseif (is_array($definition)) {
                $stack[] = $this->columnQuote($name) . ' ' . implode(' ', $definition);
            } elseif (is_string($definition)) {
                $stack[] = $this->columnQuote($name) . ' ' . $definition;
            }
        }

        if (is_array($options)) {
            $optionStack = [];

            foreach ($options as $key => $value) {
                if (is_string($value) || is_int($value)) {
                    $optionStack[] = "{$key} = {$value}";
                }
            }

            $tableOption = ' ' . implode(', ', $optionStack);
        } elseif (is_string($options)) {
            $tableOption = ' ' . $options;
        }

        $command = 'CREATE TABLE';

        if (in_array($this->type, ['mysql', 'pgsql', 'sqlite'])) {
            $command .= ' IF NOT EXISTS';
        }

        return $this->exec("{$command} {$tableName} (" . implode(', ', $stack) . "){$tableOption}");
    }

    /**
     * Drop a table.
     *
     * @param string $table
     * @return \PDOStatement|null
     */
    public function drop(string $table): ?PDOStatement
    {
        return $this->exec('DROP TABLE IF EXISTS ' . $this->tableQuote($table));
    }

    /**
     * Select data from the table.
     *
     * @param string $table
     * @param array $join
     * @param array|string $columns
     * @param array $where
     * @return array|null
     */
    public function select(string $table, $join, $columns = null, $where = null): ?array
    {
        $map = [];
        $result = [];
        $columnMap = [];

        $args = func_get_args();
        $lastArgs = $args[array_key_last($args)];
        $callback = is_callable($lastArgs) ? $lastArgs : null;

        $where = is_callable($where) ? null : $where;
        $columns = is_callable($columns) ? null : $columns;

        $column = $where === null ? $join : $columns;
        $isSingle = (is_string($column) && $column !== '*');

        $statement = $this->exec($this->selectContext($table, $map, $join, $columns, $where), $map);

        $this->columnMap($columns, $columnMap, true);

        if (!$this->statement) {
            return $result;
        }

        // @codeCoverageIgnoreStart
        if ($columns === '*') {
            if (isset($callback)) {
                while ($data = $statement->fetch(PDO::FETCH_ASSOC)) {
                    $callback($data);
                }

                return null;
            }

            return $statement->fetchAll(PDO::FETCH_ASSOC);
        }

        while ($data = $statement->fetch(PDO::FETCH_ASSOC)) {
            $currentStack = [];

            if (isset($callback)) {
                $this->dataMap($data, $columns, $columnMap, $currentStack, true);

                $callback(
                    $isSingle ?
                        $currentStack[$columnMap[$column][0]] :
                        $currentStack
                );
            } else {
                $this->dataMap($data, $columns, $columnMap, $currentStack, true, $result);
            }
        }

        if (isset($callback)) {
            return null;
        }

        if ($isSingle) {
            $singleResult = [];
            $resultKey = $columnMap[$column][0];

            foreach ($result as $item) {
                $singleResult[] = $item[$resultKey];
            }

            return $singleResult;
        }

        return $result;
    }
    // @codeCoverageIgnoreEnd

    /**
     * Insert one or more records into the table.
     *
     * @param string $table
     * @param array $values
     * @param string $primaryKey
     * @return \PDOStatement|null
     */
    public function insert(string $table, array $values, string $primaryKey = null): ?PDOStatement
    {
        $stack = [];
        $columns = [];
        $fields = [];
        $map = [];
        $returnings = [];

        if (!isset($values[0])) {
            $values = [$values];
        }

        foreach ($values as $data) {
            foreach ($data as $key => $value) {
                $columns[] = $key;
            }
        }

        $columns = array_unique($columns);

        foreach ($values as $data) {
            $values = [];

            foreach ($columns as $key) {
                $value = $data[$key];
                $type = gettype($value);

                if ($this->type === 'oracle' && $type === 'resource') {
                    $values[] = 'EMPTY_BLOB()';
                    $returnings[$this->mapKey()] = [$key, $value, PDO::PARAM_LOB];
                    continue;
                }

                if ($raw = $this->buildRaw($data[$key], $map)) {
                    $values[] = $raw;
                    continue;
                }

                $mapKey = $this->mapKey();
                $values[] = $mapKey;

                switch ($type) {

                    case 'array':
                        $map[$mapKey] = [
                            strpos($key, '[JSON]') === strlen($key) - 6 ?
                                json_encode($value) :
                                serialize($value),
                            PDO::PARAM_STR
                        ];
                        break;

                    case 'object':
                        $value = serialize($value);
                        break;

                    case 'NULL':
                    case 'resource':
                    case 'boolean':
                    case 'integer':
                    case 'double':
                    case 'string':
                        $map[$mapKey] = $this->typeMap($value, $type);
                        break;
                }
            }

            $stack[] = '(' . implode(', ', $values) . ')';
        }

        foreach ($columns as $key) {
            $fields[] = $this->columnQuote(preg_replace("/(\s*\[JSON\]$)/i", '', $key));
        }

        $query = 'INSERT INTO ' . $this->tableQuote($table) . ' (' . implode(', ', $fields) . ') VALUES ' . implode(', ', $stack);

        if (
            $this->type === 'oracle' && (!empty($returnings) || isset($primaryKey))
        ) {
            if ($primaryKey) {
                $returnings[':RETURNID'] = [$primaryKey, '', PDO::PARAM_INT, 8];
            }

            $statement = $this->returningQuery($query, $map, $returnings);

            if ($primaryKey) {
                $this->returnId = $returnings[':RETURNID'][1];
            }

            return $statement;
        }

        return $this->exec($query, $map);
    }

    /**
     * Modify data from the table.
     *
     * @param string $table
     * @param array $data
     * @param array $where
     * @return \PDOStatement|null
     */
    public function update(string $table, $data, $where = null): ?PDOStatement
    {
        $fields = [];
        $map = [];
        $returnings = [];

        foreach ($data as $key => $value) {
            $column = $this->columnQuote(preg_replace("/(\s*\[(JSON|\+|\-|\*|\/)\]$)/", '', $key));
            $type = gettype($value);

            if ($this->type === 'oracle' && $type === 'resource') {
                $fields[] = "{$column} = EMPTY_BLOB()";
                $returnings[$this->mapKey()] = [$key, $value, PDO::PARAM_LOB];
                continue;
            }

            if ($raw = $this->buildRaw($value, $map)) {
                $fields[] = "{$column} = {$raw}";
                continue;
            }

            preg_match('/(?<column>[\p{L}_][\p{L}\p{N}@$#\-_]*)(\[(?<operator>\+|\-|\*|\/)\])?/u', $key, $match);

            if (isset($match['operator'])) {
                if (is_numeric($value)) {
                    $fields[] = "{$column} = {$column} {$match['operator']} {$value}";
                }
            } else {
                $mapKey = $this->mapKey();
                $fields[] = "{$column} = {$mapKey}";

                switch ($type) {

                    case 'array':
                        $map[$mapKey] = [
                            strpos($key, '[JSON]') === strlen($key) - 6 ?
                                json_encode($value) :
                                serialize($value),
                            PDO::PARAM_STR
                        ];
                        break;

                    case 'object':
                        $value = serialize($value);

                        break;
                    case 'NULL':
                    case 'resource':
                    case 'boolean':
                    case 'integer':
                    case 'double':
                    case 'string':
                        $map[$mapKey] = $this->typeMap($value, $type);
                        break;
                }
            }
        }

        $query = 'UPDATE ' . $this->tableQuote($table) . ' SET ' . implode(', ', $fields) . $this->whereClause($where, $map);

        if ($this->type === 'oracle' && !empty($returnings)) {
            return $this->returningQuery($query, $map, $returnings);
        }

        return $this->exec($query, $map);
    }

    /**
     * Delete data from the table.
     *
     * @param string $table
     * @param array|Raw $where
     * @return \PDOStatement|null
     */
    public function delete(string $table, $where): ?PDOStatement
    {
        $map = [];

        return $this->exec('DELETE FROM ' . $this->tableQuote($table) . $this->whereClause($where, $map), $map);
    }

    /**
     * Replace old data with a new one.
     *
     * @param string $table
     * @param array $columns
     * @param array $where
     * @return \PDOStatement|null
     */
    public function replace(string $table, array $columns, $where = null): ?PDOStatement
    {
        $map = [];
        $stack = [];

        foreach ($columns as $column => $replacements) {
            if (is_array($replacements)) {
                foreach ($replacements as $old => $new) {
                    $mapKey = $this->mapKey();
                    $columnName = $this->columnQuote($column);
                    $stack[] = "{$columnName} = REPLACE({$columnName}, {$mapKey}a, {$mapKey}b)";

                    $map[$mapKey . 'a'] = [$old, PDO::PARAM_STR];
                    $map[$mapKey . 'b'] = [$new, PDO::PARAM_STR];
                }
            }
        }

        if (empty($stack)) {
            throw new InvalidArgumentException('Invalid columns supplied.');
        }

        return $this->exec('UPDATE ' . $this->tableQuote($table) . ' SET ' . implode(', ', $stack) . $this->whereClause($where, $map), $map);
    }

    /**
     * Get only one record from the table.
     *
     * @param string $table
     * @param array $join
     * @param array|string $columns
     * @param array $where
     * @return mixed
     */
    public function get(string $table, $join = null, $columns = null, $where = null)
    {
        $map = [];
        $result = [];
        $columnMap = [];
        $currentStack = [];

        if ($where === null) {
            if ($this->isJoin($join)) {
                $where['LIMIT'] = 1;
            } else {
                $columns['LIMIT'] = 1;
            }

            $column = $join;
        } else {
            $column = $columns;
            $where['LIMIT'] = 1;
        }

        $isSingle = (is_string($column) && $column !== '*');
        $query = $this->exec($this->selectContext($table, $map, $join, $columns, $where), $map);

        if (!$this->statement) {
            return false;
        }

        // @codeCoverageIgnoreStart
        $data = $query->fetchAll(PDO::FETCH_ASSOC);

        if (isset($data[0])) {
            if ($column === '*') {
                return $data[0];
            }

            $this->columnMap($columns, $columnMap, true);
            $this->dataMap($data[0], $columns, $columnMap, $currentStack, true, $result);

            if ($isSingle) {
                return $result[0][$columnMap[$column][0]];
            }

            return $result[0];
        }
    }
    // @codeCoverageIgnoreEnd

    /**
     * Determine whether the target data existed from the table.
     *
     * @param string $table
     * @param array $join
     * @param array $where
     * @return bool
     */
    public function has(string $table, $join, $where = null): bool
    {
        $map = [];
        $column = null;

        $query = $this->exec(
            $this->type === 'mssql' ?
                $this->selectContext($table, $map, $join, $column, $where, Medoo::raw('TOP 1 1')) :
                'SELECT EXISTS(' . $this->selectContext($table, $map, $join, $column, $where, 1) . ')',
            $map
        );

        if (!$this->statement) {
            return false;
        }

        // @codeCoverageIgnoreStart
        $result = $query->fetchColumn();

        return $result === '1' || $result === 1 || $result === true;
    }
    // @codeCoverageIgnoreEnd

    /**
     * Randomly fetch data from the table.
     *
     * @param string $table
     * @param array $join
     * @param array|string $columns
     * @param array $where
     * @return array
     */
    public function rand(string $table, $join = null, $columns = null, $where = null): array
    {
        $orderRaw = $this->raw(
            $this->type === 'mysql' ? 'RAND()'
                : ($this->type === 'mssql' ? 'NEWID()'
                    : 'RANDOM()')
        );

        if ($where === null) {
            if ($this->isJoin($join)) {
                $where['ORDER'] = $orderRaw;
            } else {
                $columns['ORDER'] = $orderRaw;
            }
        } else {
            $where['ORDER'] = $orderRaw;
        }

        return $this->select($table, $join, $columns, $where);
    }

    /**
     * Build for the aggregate function.
     *
     * @param string $type
     * @param string $table
     * @param array $join
     * @param string $column
     * @param array $where
     * @return string|null
     */
    private function aggregate(string $type, string $table, $join = null, $column = null, $where = null): ?string
    {
        $map = [];

        $query = $this->exec($this->selectContext($table, $map, $join, $column, $where, $type), $map);

        if (!$this->statement) {
            return null;
        }

        // @codeCoverageIgnoreStart
        return (string) $query->fetchColumn();
    }
    // @codeCoverageIgnoreEnd

    /**
     * Count the number of rows from the table.
     *
     * @param string $table
     * @param array $join
     * @param string $column
     * @param array $where
     * @return int|null
     */
    public function count(string $table, $join = null, $column = null, $where = null): ?int
    {
        return (int) $this->aggregate('COUNT', $table, $join, $column, $where);
    }

    /**
     * Calculate the average value of the column.
     *
     * @param string $table
     * @param array $join
     * @param string $column
     * @param array $where
     * @return string|null
     */
    public function avg(string $table, $join, $column = null, $where = null): ?string
    {
        return $this->aggregate('AVG', $table, $join, $column, $where);
    }

    /**
     * Get the maximum value of the column.
     *
     * @param string $table
     * @param array $join
     * @param string $column
     * @param array $where
     * @return string|null
     */
    public function max(string $table, $join, $column = null, $where = null): ?string
    {
        return $this->aggregate('MAX', $table, $join, $column, $where);
    }

    /**
     * Get the minimum value of the column.
     *
     * @param string $table
     * @param array $join
     * @param string $column
     * @param array $where
     * @return string|null
     */
    public function min(string $table, $join, $column = null, $where = null): ?string
    {
        return $this->aggregate('MIN', $table, $join, $column, $where);
    }

    /**
     * Calculate the total value of the column.
     *
     * @param string $table
     * @param array $join
     * @param string $column
     * @param array $where
     * @return string|null
     */
    public function sum(string $table, $join, $column = null, $where = null): ?string
    {
        return $this->aggregate('SUM', $table, $join, $column, $where);
    }

    /**
     * Start a transaction.
     *
     * @param callable $actions
     * @codeCoverageIgnore
     * @return void
     */
    public function action(callable $actions): void
    {
        if (is_callable($actions)) {
            $this->pdo->beginTransaction();

            try {
                $result = $actions($this);

                if ($result === false) {
                    $this->pdo->rollBack();
                } else {
                    $this->pdo->commit();
                }
            } catch (Exception $e) {
                $this->pdo->rollBack();
                throw $e;
            }
        }
    }

    /**
     * Return the ID for the last inserted row.
     *
     * @param string $name
     * @codeCoverageIgnore
     * @return string|null
     */
    public function id(string $name = null): ?string
    {
        $type = $this->type;

        if ($type === 'oracle') {
            return $this->returnId;
        } elseif ($type === 'pgsql') {
            $id = $this->pdo->query('SELECT LASTVAL()')->fetchColumn();

            return (string) $id ?: null;
        }

        return $this->pdo->lastInsertId($name);
    }

    /**
     * Enable debug mode and output readable statement string.
     *
     * @codeCoverageIgnore
     * @return Medoo
     */
    public function debug(): self
    {
        $this->debugMode = true;

        return $this;
    }

    /**
     * Enable debug logging mode.
     *
     * @codeCoverageIgnore
     * @return void
     */
    public function beginDebug(): void
    {
        $this->debugMode = true;
        $this->debugLogging = true;
    }

    /**
     * Disable debug logging and return all readable statements.
     *
     * @codeCoverageIgnore
     * @return void
     */
    public function debugLog(): array
    {
        $this->debugMode = false;
        $this->debugLogging = false;

        return $this->debugLogs;
    }

    /**
     * Return the last performed statement.
     *
     * @codeCoverageIgnore
     * @return string|null
     */
    public function last(): ?string
    {
        if (empty($this->logs)) {
            return null;
        }

        $log = $this->logs[array_key_last($this->logs)];

        return $this->generate($log[0], $log[1]);
    }

    /**
     * Return all executed statements.
     *
     * @codeCoverageIgnore
     * @return string[]
     */
    public function log(): array
    {
        return array_map(
            function ($log) {
                return $this->generate($log[0], $log[1]);
            },
            $this->logs
        );
    }

    /**
     * Get information about the database connection.
     *
     * @codeCoverageIgnore
     * @return array
     */
    public function info(): array
    {
        $output = [
            'server' => 'SERVER_INFO',
            'driver' => 'DRIVER_NAME',
            'client' => 'CLIENT_VERSION',
            'version' => 'SERVER_VERSION',
            'connection' => 'CONNECTION_STATUS'
        ];

        foreach ($output as $key => $value) {
            try {
                $output[$key] = $this->pdo->getAttribute(constant('PDO::ATTR_' . $value));
            } catch (PDOException $e) {
                $output[$key] = $e->getMessage();
            }
        }

        $output['dsn'] = $this->dsn;

        return $output;
    }
}
