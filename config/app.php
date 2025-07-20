<?php
/**
 * Application Configuration
 * 
 * This file contains all configuration settings and demonstrates:
 * 1. Environment configuration
 * 2. Security settings
 * 3. Database configuration
 * 4. Session configuration
 * 5. Common utility functions used throughout the application
 */

// Environment Configuration
define('DEBUG_MODE', true); // Set to false in production
define('APP_NAME', 'PHP Bug Bounty Learning Environment');
define('APP_VERSION', '1.0.0');
define('APP_URL', 'http://localhost:8080');

// Security Configuration
define('SECRET_KEY', 'your-secret-key-change-this-in-production');
define('SESSION_TIMEOUT', 3600); // 1 hour in seconds
define('RATE_LIMIT_MAX', 100); // Maximum requests per session
define('MAX_FILE_SIZE', 5 * 1024 * 1024); // 5MB
define('ALLOWED_FILE_TYPES', ['jpg', 'jpeg', 'png', 'gif', 'pdf', 'txt']);

// Paths
define('ROOT_PATH', dirname(__DIR__));

// Database Configuration
define('DB_TYPE', 'sqlite'); // Changed from mysql to sqlite for easier setup
define('DB_HOST', 'localhost');
define('DB_NAME', ROOT_PATH . '/database.sqlite');
define('DB_USER', 'root');
define('DB_PASS', '');
define('DB_CHARSET', 'utf8mb4');
define('VIEW_PATH', ROOT_PATH . '/views');
define('UPLOAD_PATH', ROOT_PATH . '/uploads');
define('LOG_PATH', ROOT_PATH . '/logs');

// Error handling
if (DEBUG_MODE) {
    ini_set('display_errors', 1);
    ini_set('display_startup_errors', 1);
    error_reporting(E_ALL);
} else {
    ini_set('display_errors', 0);
    ini_set('display_startup_errors', 0);
    error_reporting(E_ALL & ~E_NOTICE & ~E_STRICT & ~E_DEPRECATED);
}

// Create necessary directories
if (!is_dir(UPLOAD_PATH)) {
    mkdir(UPLOAD_PATH, 0755, true);
}
if (!is_dir(LOG_PATH)) {
    mkdir(LOG_PATH, 0755, true);
}

/**
 * CSRF Token Functions
 * Demonstrates proper CSRF protection implementation
 */
function generateCSRFToken() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCSRFToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

/**
 * Input Sanitization Functions
 * Shows secure and insecure ways to handle user input
 */

// Secure input sanitization
function sanitizeInput($input, $type = 'string') {
    switch ($type) {
        case 'string':
            return htmlspecialchars(strip_tags(trim($input)), ENT_QUOTES, 'UTF-8');
        case 'email':
            return filter_var($input, FILTER_SANITIZE_EMAIL);
        case 'url':
            return filter_var($input, FILTER_SANITIZE_URL);
        case 'int':
            return filter_var($input, FILTER_SANITIZE_NUMBER_INT);
        case 'float':
            return filter_var($input, FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION);
        default:
            return htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
    }
}

// Insecure input handling (for vulnerability demonstration)
function unsanitizedInput($input) {
    return $input; // No sanitization - vulnerable to XSS
}

/**
 * Validation Functions
 */
function validateEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL);
}

function validatePassword($password) {
    // Basic password requirements
    return strlen($password) >= 8 && 
           preg_match('/[A-Z]/', $password) && 
           preg_match('/[a-z]/', $password) && 
           preg_match('/[0-9]/', $password);
}

function validateFileUpload($file) {
    $errors = [];
    
    // Check file size
    if ($file['size'] > MAX_FILE_SIZE) {
        $errors[] = 'File size exceeds maximum allowed size';
    }
    
    // Check file type
    $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    if (!in_array($extension, ALLOWED_FILE_TYPES)) {
        $errors[] = 'File type not allowed';
    }
    
    // Check for upload errors
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $errors[] = 'File upload error: ' . $file['error'];
    }
    
    return empty($errors) ? true : $errors;
}

/**
 * Logging Functions
 */
function logSecurityEvent($event, $data = []) {
    $logEntry = [
        'timestamp' => date('Y-m-d H:i:s'),
        'event' => $event,
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
        'session_id' => session_id(),
        'data' => $data
    ];
    
    $logFile = LOG_PATH . '/security.log';
    file_put_contents($logFile, json_encode($logEntry) . "\n", FILE_APPEND | LOCK_EX);
}

function logSQLQuery($query, $params = [], $execution_time = 0) {
    if (!DEBUG_MODE) return;
    
    $logEntry = [
        'timestamp' => date('Y-m-d H:i:s'),
        'query' => $query,
        'params' => $params,
        'execution_time' => $execution_time,
        'backtrace' => debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 3)
    ];
    
    $logFile = LOG_PATH . '/sql.log';
    file_put_contents($logFile, json_encode($logEntry) . "\n", FILE_APPEND | LOCK_EX);
}

/**
 * HTTP Response Functions
 */
function jsonResponse($data, $statusCode = 200) {
    http_response_code($statusCode);
    header('Content-Type: application/json');
    echo json_encode($data, JSON_PRETTY_PRINT);
    exit;
}

function redirectTo($url, $statusCode = 302) {
    http_response_code($statusCode);
    header('Location: ' . $url);
    exit;
}

function setSecurityHeaders() {
    // Security headers to prevent common attacks
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('X-XSS-Protection: 1; mode=block');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    
    if (!DEBUG_MODE) {
        header('Content-Security-Policy: default-src \'self\'; script-src \'self\' \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\';');
    }
}

/**
 * Rate Limiting Functions
 */
function checkRateLimit($identifier, $maxRequests = RATE_LIMIT_MAX, $timeWindow = 3600) {
    $key = 'rate_limit_' . $identifier;
    $current = $_SESSION[$key] ?? ['count' => 0, 'start' => time()];
    
    // Reset if time window has passed
    if (time() - $current['start'] > $timeWindow) {
        $current = ['count' => 0, 'start' => time()];
    }
    
    $current['count']++;
    $_SESSION[$key] = $current;
    
    if ($current['count'] > $maxRequests) {
        logSecurityEvent('rate_limit_exceeded', [
            'identifier' => $identifier,
            'count' => $current['count'],
            'max' => $maxRequests
        ]);
        return false;
    }
    
    return true;
}

/**
 * Password Functions
 */
function hashPassword($password) {
    return password_hash($password, PASSWORD_DEFAULT);
}

function verifyPassword($password, $hash) {
    return password_verify($password, $hash);
}

// Weak password hashing (for vulnerability demonstration)
function weakHashPassword($password) {
    return md5($password); // Vulnerable - MD5 is weak
}

/**
 * String Functions
 */
function generateRandomString($length = 32) {
    return bin2hex(random_bytes($length / 2));
}

function truncateString($string, $length = 100, $suffix = '...') {
    return strlen($string) > $length ? substr($string, 0, $length) . $suffix : $string;
}

/**
 * Helper function for older PHP versions
 */
if (!function_exists('getallheaders')) {
    function getallheaders() {
        $headers = [];
        foreach ($_SERVER as $name => $value) {
            if (substr($name, 0, 5) == 'HTTP_') {
                $headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))))] = $value;
            }
        }
        return $headers;
    }
}

/**
 * VULNERABILITY DEMONSTRATION FUNCTIONS
 * These are intentionally insecure for learning purposes
 */

// SQL Injection vulnerable function
function vulnerableQuery($query, $params = []) {
    // WARNING: This is vulnerable to SQL injection
    return $query; // Returns raw query without preparation
}

// XSS vulnerable function  
function vulnerableOutput($input) {
    // WARNING: This is vulnerable to XSS
    return $input; // No escaping
}

// Path traversal vulnerable function
function vulnerableFileInclude($file) {
    // WARNING: This is vulnerable to LFI/RFI
    include $file;
}

/**
 * LEARNING NOTES:
 * 
 * 1. Always use prepared statements for database queries
 * 2. Escape output with htmlspecialchars() or equivalent
 * 3. Validate and sanitize all user inputs
 * 4. Use strong password hashing (password_hash/password_verify)
 * 5. Implement proper session management
 * 6. Set security headers
 * 7. Log security events for monitoring
 * 8. Use CSRF tokens for state-changing operations
 * 9. Implement rate limiting
 * 10. Never trust user input
 */
?>