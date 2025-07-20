<?php
/**
 * Main Entry Point - HTTP Workflow Demonstration
 * 
 * This file demonstrates:
 * 1. How browsers create HTTP requests
 * 2. How web applications handle those requests
 * 3. The complete request/response lifecycle
 * 4. Routing and middleware execution
 */

// Start output buffering to control when content is sent
ob_start();

// Error reporting based on environment
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Start session early for session management demo
session_start();

// Load configuration and core classes
require_once 'config/app.php';
require_once 'core/Router.php';
require_once 'core/Template.php';
require_once 'core/Session.php';
require_once 'core/Database.php';

// Load controllers
require_once 'controllers/HomeController.php';

/**
 * HTTP WORKFLOW DEMONSTRATION
 * 
 * 1. Browser sends HTTP request to server
 * 2. Server receives request and extracts information
 * 3. Application routes request to appropriate handler
 * 4. Middleware processes request (auth, CSRF, etc.)
 * 5. Controller processes business logic
 * 6. View renders response
 * 7. Server sends HTTP response back to browser
 */

// Step 1: Capture HTTP request information
$httpInfo = [
    'method' => $_SERVER['REQUEST_METHOD'],
    'uri' => $_SERVER['REQUEST_URI'],
    'query_string' => $_SERVER['QUERY_STRING'] ?? '',
    'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
    'remote_addr' => $_SERVER['REMOTE_ADDR'] ?? '',
    'timestamp' => date('Y-m-d H:i:s'),
    'headers' => getallheaders(),
    'post_data' => $_POST,
    'get_data' => $_GET,
    'cookies' => $_COOKIE,
    'session_id' => session_id(),
    'content_type' => $_SERVER['CONTENT_TYPE'] ?? 'Not set',
    'content_length' => $_SERVER['CONTENT_LENGTH'] ?? 0
];

// Log request for debugging (in real bug bounty, this helps understand the application)
if (DEBUG_MODE) {
    error_log("HTTP Request: " . json_encode($httpInfo, JSON_PRETTY_PRINT));
}

// Step 2: Initialize core components
$router = new Router();
$session = new Session();
$template = new Template();

// Step 3: Set up routes (URL to controller mapping)
// This demonstrates how different URLs map to different functionality

// Home routes
$router->get('/', 'HomeController@index');
$router->get('/http-info', 'HomeController@httpInfo');

// Demonstration routes for bug bounty learning
$router->get('/demo/sql-injection', 'HomeController@sqlInjectionDemo');
$router->get('/demo/xss', 'HomeController@xssDemo');
$router->get('/demo/csrf', 'HomeController@csrfDemo');
$router->get('/demo/session', 'HomeController@sessionDemo');

// API routes (common in modern web apps)
$router->get('/api/users', 'HomeController@apiUsers');
$router->post('/api/login', 'HomeController@apiLogin');

// File operations (often vulnerable in web apps)
$router->get('/files', 'HomeController@fileList');
$router->post('/upload', 'HomeController@fileUpload');

// Admin routes (access control testing)
$router->get('/admin', 'HomeController@admin');
$router->get('/admin/users', 'HomeController@adminUsers');

// Step 4: Middleware execution (security layers)
// In bug bounty, understanding middleware helps identify bypass opportunities

$middlewareStack = [];

// Rate limiting middleware (prevents brute force)
$middlewareStack[] = function($request, $next) {
    $ip = $_SERVER['REMOTE_ADDR'];
    $requests = $_SESSION['rate_limit'][$ip] ?? 0;
    
    if ($requests > RATE_LIMIT_MAX) {
        http_response_code(429);
        die(json_encode(['error' => 'Rate limit exceeded']));
    }
    
    $_SESSION['rate_limit'][$ip] = $requests + 1;
    return $next($request);
};

// CSRF protection middleware (when not in safe methods)
if (!in_array($_SERVER['REQUEST_METHOD'], ['GET', 'HEAD', 'OPTIONS'])) {
    $middlewareStack[] = function($request, $next) {
        if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'] ?? '', $_POST['csrf_token'])) {
            http_response_code(403);
            die(json_encode(['error' => 'CSRF token validation failed']));
        }
        return $next($request);
    };
}

// Authentication middleware for protected routes
$protectedRoutes = ['/admin', '/admin/users', '/api/users'];
if (in_array(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH), $protectedRoutes)) {
    $middlewareStack[] = function($request, $next) use ($session) {
        if (!$session->isAuthenticated()) {
            http_response_code(401);
            die(json_encode(['error' => 'Authentication required']));
        }
        return $next($request);
    };
}

// Step 5: Execute middleware stack
$executeMiddleware = function($middlewareStack, $request) {
    $next = function($request) {
        return $request; // Final step - just return the request
    };
    
    // Build the middleware stack in reverse order
    for ($i = count($middlewareStack) - 1; $i >= 0; $i--) {
        $middleware = $middlewareStack[$i];
        $currentNext = $next;
        $next = function($request) use ($middleware, $currentNext) {
            return $middleware($request, $currentNext);
        };
    }
    
    return $next($request);
};

// Execute middleware
try {
    $executeMiddleware($middlewareStack, $_REQUEST);
} catch (Exception $e) {
    http_response_code(500);
    if (DEBUG_MODE) {
        die("Middleware Error: " . $e->getMessage());
    } else {
        die("Internal Server Error");
    }
}

// Step 6: Route the request
try {
    $result = $router->dispatch($_SERVER['REQUEST_METHOD'], $_SERVER['REQUEST_URI']);
    
    // Store routing info for debugging
    if (DEBUG_MODE) {
        $_SESSION['last_route'] = [
            'method' => $_SERVER['REQUEST_METHOD'],
            'uri' => $_SERVER['REQUEST_URI'],
            'handler' => $result['handler'] ?? 'Not found',
            'params' => $result['params'] ?? [],
            'timestamp' => time()
        ];
    }
    
} catch (Exception $e) {
    // Step 7: Error handling (important for information disclosure bugs)
    http_response_code(500);
    
    if (DEBUG_MODE) {
        // In debug mode, show detailed error (potential information disclosure)
        echo "<h1>Application Error</h1>";
        echo "<p><strong>Message:</strong> " . htmlspecialchars($e->getMessage()) . "</p>";
        echo "<p><strong>File:</strong> " . htmlspecialchars($e->getFile()) . "</p>";
        echo "<p><strong>Line:</strong> " . $e->getLine() . "</p>";
        echo "<h3>Stack Trace:</h3>";
        echo "<pre>" . htmlspecialchars($e->getTraceAsString()) . "</pre>";
        echo "<h3>HTTP Request Info:</h3>";
        echo "<pre>" . htmlspecialchars(json_encode($httpInfo, JSON_PRETTY_PRINT)) . "</pre>";
    } else {
        // In production mode, show generic error (secure)
        echo "<h1>Oops! Something went wrong</h1>";
        echo "<p>Please try again later.</p>";
        
        // Log detailed error for developers
        error_log("Application Error: " . $e->getMessage() . " in " . $e->getFile() . " on line " . $e->getLine());
    }
}

// Clean up output buffer
ob_end_flush();

/**
 * LEARNING NOTES FOR BUG BOUNTY HUNTERS:
 * 
 * 1. HTTP Workflow Understanding:
 *    - Every request goes through this complete lifecycle
 *    - Understanding each step helps identify attack vectors
 *    - Middleware order matters for security bypasses
 * 
 * 2. Common Attack Vectors:
 *    - Route parameter manipulation
 *    - Middleware bypass attempts  
 *    - Session manipulation
 *    - Header injection
 *    - Error message information disclosure
 * 
 * 3. Testing Methodology:
 *    - Map all routes and endpoints
 *    - Test authentication/authorization on each route
 *    - Try different HTTP methods (GET, POST, PUT, DELETE, PATCH)
 *    - Analyze error responses in different modes
 *    - Test rate limiting and CSRF protection
 * 
 * 4. Tools to Use:
 *    - Burp Suite for request manipulation
 *    - Browser DevTools for HTTP analysis
 *    - curl for specific request testing
 *    - ffuf/gobuster for endpoint discovery
 */
?>