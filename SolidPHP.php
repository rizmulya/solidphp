<?php

/**
 * SolidPHP
 * is The Most Lightweight and Efficient PHP Micro Framework
 * https://github.com/rizmulya/solidphp
 */

namespace SolidPHP;

use Exception;
use Throwable;
use mysqli;

/**
 * Perform simplified, secure, original MySQLi database operations with defined fields and data types.
 * 
 * @method mixed query($query)                          Original mysqli query()
 * @method mixed prepare($query)                        Original mysqli prepare()
 * @method mixed bind_param($tableName, ...$params)     Modied mysqli bind_param()
 * @method mixed execute()                              Original mysqli execute()
 * @method mixed close()                                Original mysqli $stmt close()
 * @method mixed shutdown()                             Original mysqli close() connection
 * @method mixed getStmt()                              Original mysqli $stmt
 * @method mixed get_result()                           Original mysqli get_result()
 * @method mixed table($tableName, array $fields)       Define the table for efficiency
 * @method string fields($tableName, $exclude = [])     Get fields name based on defined table.
 * @method string setClause($tableName, $exclude = [])  Generate SET Clause based on defined table.
 */
class DBMysql
{
    private $mysqli;
    private $stmt;
    private $isClosed = false;
    private $fields = [];

    public function __construct($config = [])
    {
        $this->mysqli = new mysqli($config['host'], $config['username'], $config['password'], $config['database']);
        if ($this->mysqli->connect_error) {
            die("Connection failed: " . $this->mysqli->connect_error);
        }
    }

    /**
     * original mysqli query()
     */
    public function query($query)
    {
        return $this->mysqli->query($query);
        return $this;
    }


    /**
     * original mysqli prepare()
     */
    public function prepare($query)
    {
        $this->stmt = $this->mysqli->prepare($query);
        return $this;
    }

    /**
     * modified mysqli bind_param()
     * @param string $tableName: defined tableName or raw data type
     * @param array $params
     */
    public function bind_param($tableName, ...$params)
    {
        $types = '';
        $typedParams = [];

        if (isset($this->fields[$tableName])) { // use table name
            foreach (array_values($this->fields[$tableName]) as $index => $type) {
                $types .= $type;
                $typedParams[] = $params[$index];
            }
        } else {
            $types = $tableName; // use raw
            $typedParams = $params;
        }

        $this->stmt->bind_param($types, ...$typedParams);
        return $this;
    }

    /**
     * original mysqli execute()
     */
    public function execute()
    {
        $this->stmt->execute();
        return $this;
    }

    /**
     * original mysqli close()
     */
    public function close()
    {
        if ($this->stmt) {
            $this->stmt->close();
            $this->stmt = null;
        }
        return $this;
    }

    /**
     * original mysqli close() connection
     */
    public function shutdown()
    {
        if (!$this->isClosed) {
            $this->close();
            $this->mysqli->close();
            $this->isClosed = true;
        }
        return $this;
    }

    /**
     * original mysqli $stmt
     */
    public function getStmt()
    {
        return $this->stmt;
    }

    /**
     * original mysqli get_result()
     */
    public function get_result()
    {
        return $this->stmt ? $this->stmt->get_result() : null;
    }

    /**
     * Define the table for efficiency and bind_param() purposes.
     * @param string $tableName
     * @param array $fields['field1' => 'type1']
     * - type 'i' is used for an integer (123)
     * - type 'd' is used for a double (3.14)
     * - type 's' is used for a string ('sample')
     * - type 'b' is used for binary data (file_get_content())
     */
    public function table($tableName, array $fields)
    {
        $this->fields[$tableName] = $fields;
        return $this;
    }


    /**
     * Get fields name based on defined table.
     * @param string $tableName
     * @param array $exclude
     * @return string imploded fields 'a, b, c'
     */
    public function fields($tableName, $exclude = [])
    {
        if (!isset($this->fields[$tableName])) return '';
        $fields = self::filterFields($this->fields[$tableName], $exclude);
        return implode(", ", array_keys($fields));
    }

    /**
     * Generate SET Clause based on defined table.
     *
     * @param string $tableName
     * @param array $exclude
     * @return string SET Clause 'a = ?, b = ?'
     */
    public function setClause($tableName, $exclude = [])
    {
        if (!isset($this->fields[$tableName])) return '';
        $fields = self::filterFields($this->fields[$tableName], $exclude);
        return implode(' = ?, ', array_keys($fields)) . ' = ?';
    }

    private static function filterFields($fields, $exclude)
    {
        return array_diff_key($fields, array_flip($exclude));
    }
}


/**
 * React Vite Adaptor
 */
class Vite
{
    private static $devServer = 'http://localhost:5173';
    private static $manifestPath = __DIR__ . '/react/dist/.vite/manifest.json';
    private static $viteConfigPath = __DIR__ . '/react/vite.config.js';
    private static $distPath = '/react/dist/';

    /**
     * @param array $config['devServer'] 
     * @param array $config['manifestPath']
     * @param array $config['viteConfigPath']
     * @param array $config['distPath']
     */
    public static function set($config = [])
    {
        self::$devServer = $config['devServer'] ?? self::$devServer;
        self::$manifestPath = $config['manifestPath'] ?? self::$manifestPath;
        self::$viteConfigPath = $config['viteConfigPath'] ?? self::$viteConfigPath;
        self::$distPath = $config['distPath'] ?? self::$distPath;
    }

    /**
     * Auto modify vite.config.js based on APP_DEBUG
     */
    // public static function autoConfig()
    // {
    //     if (!file_exists(self::$viteConfigPath)) {
    //         echo "File not found: " . self::$viteConfigPath;
    //         return;
    //     }

    //     $content = file_get_contents(self::$viteConfigPath);

    //     if (APP_DEBUG) {
    //         $content = preg_replace('/^(?!\/\/)(\s*base:\s*\'[^\']*\',\s*)$/m', '// $1', $content);
    //     } else {
    //         $content = preg_replace('/^\s*\/\/\s*(base:\s*\'[^\']*\',\s*)$/m', '$1', $content);
    //     }

    //     file_put_contents(self::$viteConfigPath, $content);
    // }

    /**
     * React vite header
     */
    public static function header()
    {
        if (APP_DEBUG) {
            echo '
            <link rel="icon" type="image/svg+xml" href="' . self::$devServer . '/vite.svg" />
            <script type="module">
                import RefreshRuntime from "' . self::$devServer . '/@react-refresh"
                RefreshRuntime.injectIntoGlobalHook(window)
                window.$RefreshReg$ = () => {}
                window.$RefreshSig$ = () => (type) => type
                window.__vite_plugin_react_preamble_installed__ = true
            </script>
            <script type="module" src="' . self::$devServer . '/@vite/client"></script>';
        }
        if (!APP_DEBUG) {
            echo '<script type="module" crossorigin src="' . Route::is(rtrim(self::$distPath, '/') . '/' . self::asset('index.html')) . '"></script>
            <link rel="stylesheet" crossorigin href="' . Route::is(rtrim(self::$distPath, '/') . '/' . self::asset('index.html', 'css')[0]) . '" />';
        }
    }

    /**
     * React vite footer script
     */
    public static function footer($src = 'src/main.jsx')
    {
        if (APP_DEBUG) {
            echo '<script type="module" src="' . self::asset($src) . '"></script>';
        }
    }

    /**
     * Get vite asset
     */
    private static function asset($asset, $type = 'file')
    {
        if (APP_DEBUG) {
            if ($type === 'css') {
                return [];
            }
            return self::$devServer . "/$asset";
        } else {
            $manifest = json_decode(file_get_contents(self::$manifestPath), true);
            if (isset($manifest[$asset])) {
                return $manifest[$asset][$type];
            }
            return null;
        }
    }
}

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

    /**
     * Add an encrypted field to the given array data
     * @param array $data The data to be processed
     * @param string $sourceField The field to be encrypted
     * @param string $newField The new field to store the encrypted value
     * @return array The processed data with the new encrypted field
     */
    public function addEncryptedField(array $data, $sourceField, $newField)
    {
        if (isset($data[0]) && is_array($data[0])) {
            foreach ($data as &$row) {
                $row[$newField] = $this->encrypt($row[$sourceField]);
            }
        } else {
            $data[$newField] = $this->encrypt($data[$sourceField]);
        }
        return $data;
    }
}


/**
 * JWT Token Engine
 */
class JWT
{
    private static $cookieName = 'webToken';
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
        } catch (Throwable $th) {
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

    /**
     * Get verified user
     */
    public static function getUser()
    {
        return self::decode(self::getToken());
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
 * Route Helper
 * @method string is($param)        Build a full URL from a given parameter.
 * @method string current()         Get the full current URL.
 * @method bool equals($url)        Check if the current URL equals the given parameter.
 * @method bool contains($string)   Check if the current URL contains the given parameter.
 */
class Route
{
    /**
     * Build a full URL from a given parameter.
     *
     * @param string $param
     * @return string
     */
    public static function is($param)
    {
        return rtrim(APP_URL, '/') . '/' . ltrim($param, '/');
    }

    /**
     * Get the full current URL.
     *
     * @return string
     */
    public static function current()
    {
        $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' || $_SERVER['SERVER_PORT'] == 443) ? "https://" : "http://";
        $url = $protocol . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
        return $url;
    }

    /**
     * Check if the current URL equals the given parameter.
     *
     * @param string $url Full URL
     * @return bool
     */
    public static function equals($url)
    {
        return self::current() === $url;
    }

    /**
     * Check if the current URL contains the given parameter.
     *
     * @param string $string
     * @return bool
     */
    public static function contains($string)
    {
        return strpos(self::current(), $string) !== false;
    }
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
        $this->currentPath = $_SERVER['PATH_INFO'] ?? str_replace(parse_url(APP_URL, PHP_URL_PATH) ?: '', '', $_SERVER["REQUEST_URI"]);
        $this->request["body"] = $_POST ?? [];
        $this->request["raw"] = file_get_contents('php://input');
        $this->request["params"] = $_GET ?? [];
        $this->request["files"] = $_FILES ?? [];
        $this->request["cookies"] = $_COOKIE ?? [];
        $this->response = new Response();
        $this->routes = ['GET' => [], 'POST' => [], 'PUT' => [], 'DELETE' => [], 'PATCH' => [], 'ANY' => [], 'RE' => []];
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

    public function rePath($regex, ...$callback)
    {
        $this->routes['RE'][$regex] = $callback;
    }

    private function getCallback($method)
    {
        if (!isset($this->routes[$method])) return null;
        foreach ([$method, 'RE'] as $method) {
            if (!isset($this->routes[$method])) continue;
            foreach ($this->routes[$method] as $pattern => $callbacks) {
                if (preg_match($pattern, $this->currentPath, $matches)) {
                    $this->request["params"] = array_filter($matches, 'is_string', ARRAY_FILTER_USE_KEY);
                    return $callbacks;
                }
            }
            if ($method === 'ANY') break;
        }
        return null;
    }

    public function start()
    {
        if (!APP_DEBUG) {
            error_reporting(0);
            ini_set('display_errors', 0);
        }
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
        header('Content-Type: application/json');
        if ($status !== null) {
            http_response_code($status);
        }
        return print(json_encode($data));
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
     * @return void header location to the given $path
     */
    public function redirect($path)
    {
        return header('Location: ' . $path);
    }

    /**
     * @return void PHP page with Templating Engine
     */
    public function view($page, $data = [])
    {
        Section::render($page, $data);
    }

    /**
     * Return PHP single file
     */
    public function php($file, $status = null)
    {
        if ($status !== null) {
            http_response_code($status);
        }
        ob_start();
        include $file;
        $content = ob_get_clean();
        return print($content);
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
        $pageContent = ob_get_clean();

        if (self::$layout) {
            include self::$layout;
        } else {
            echo $pageContent;
        }
    }

    /**
     * Include a php file with the given data
     */
    public static function include($file, $data = [])
    {
        extract($data);
        include $file;
    }
}
