<?php
/**
 * Router Class - URL Routing and Request Handling
 * 
 * This class demonstrates:
 * 1. URL routing and pattern matching
 * 2. Parameter extraction from URLs
 * 3. Middleware execution
 * 4. Controller method invocation
 * 5. Common routing vulnerabilities and protections
 */

class Router {
    private $routes = [];
    private $middleware = [];
    private $currentRoute = null;
    
    /**
     * Register a GET route
     */
    public function get($pattern, $handler) {
        $this->addRoute('GET', $pattern, $handler);
    }
    
    /**
     * Register a POST route
     */
    public function post($pattern, $handler) {
        $this->addRoute('POST', $pattern, $handler);
    }
    
    /**
     * Register a PUT route
     */
    public function put($pattern, $handler) {
        $this->addRoute('PUT', $pattern, $handler);
    }
    
    /**
     * Register a DELETE route
     */
    public function delete($pattern, $handler) {
        $this->addRoute('DELETE', $pattern, $handler);
    }
    
    /**
     * Register any HTTP method route
     */
    public function any($pattern, $handler) {
        $methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'];
        foreach ($methods as $method) {
            $this->addRoute($method, $pattern, $handler);
        }
    }
    
    /**
     * Add a route to the routing table
     */
    private function addRoute($method, $pattern, $handler) {
        // Convert route pattern to regex for parameter extraction
        // Example: /user/{id} becomes /user/([^/]+)
        $regex = preg_replace('/\{([a-zA-Z0-9_]+)\}/', '([^/]+)', $pattern);
        $regex = '#^' . $regex . '$#';
        
        $this->routes[] = [
            'method' => $method,
            'pattern' => $pattern,
            'regex' => $regex,
            'handler' => $handler,
            'middleware' => []
        ];
        
        if (DEBUG_MODE) {
            error_log("Route registered: $method $pattern -> $handler");
        }
    }
    
    /**
     * Add middleware to the last registered route
     */
    public function middleware($middleware) {
        if (!empty($this->routes)) {
            $lastIndex = count($this->routes) - 1;
            $this->routes[$lastIndex]['middleware'][] = $middleware;
        }
        return $this;
    }
    
    /**
     * Dispatch the request to the appropriate handler
     */
    public function dispatch($method, $uri) {
        // Clean the URI and extract path
        $path = parse_url($uri, PHP_URL_PATH);
        $path = rtrim($path, '/') ?: '/';
        
        // Log the routing attempt
        if (DEBUG_MODE) {
            error_log("Routing: $method $path");
        }
        
        // Find matching route
        foreach ($this->routes as $route) {
            if ($route['method'] === $method && preg_match($route['regex'], $path, $matches)) {
                $this->currentRoute = $route;
                
                // Extract parameters from URL
                $params = $this->extractParameters($route['pattern'], $path);
                
                // Execute route middleware
                foreach ($route['middleware'] as $middleware) {
                    $this->executeMiddleware($middleware, $params);
                }
                
                // Execute the handler
                return $this->executeHandler($route['handler'], $params);
            }
        }
        
        // No route found - 404
        $this->handle404($method, $path);
    }
    
    /**
     * Extract parameters from URL based on route pattern
     */
    private function extractParameters($pattern, $path) {
        $params = [];
        
        // Extract parameter names from pattern
        preg_match_all('/\{([a-zA-Z0-9_]+)\}/', $pattern, $paramNames);
        
        // Extract values from path
        $regex = preg_replace('/\{([a-zA-Z0-9_]+)\}/', '([^/]+)', $pattern);
        $regex = '#^' . $regex . '$#';
        
        if (preg_match($regex, $path, $matches)) {
            array_shift($matches); // Remove full match
            
            for ($i = 0; $i < count($paramNames[1]); $i++) {
                if (isset($matches[$i])) {
                    $params[$paramNames[1][$i]] = $matches[$i];
                }
            }
        }
        
        return $params;
    }
    
    /**
     * Execute middleware
     */
    private function executeMiddleware($middleware, $params) {
        if (is_callable($middleware)) {
            $middleware($params);
        } elseif (is_string($middleware)) {
            // Instantiate middleware class
            if (class_exists($middleware)) {
                $middlewareInstance = new $middleware();
                if (method_exists($middlewareInstance, 'handle')) {
                    $middlewareInstance->handle($params);
                }
            }
        }
    }
    
    /**
     * Execute the route handler
     */
    private function executeHandler($handler, $params) {
        if (is_callable($handler)) {
            // Closure handler
            return $handler($params);
        } elseif (is_string($handler)) {
            // Controller@method format
            if (strpos($handler, '@') !== false) {
                list($controllerName, $method) = explode('@', $handler);
                
                // Security: Validate controller and method names
                if (!$this->isValidControllerName($controllerName) || !$this->isValidMethodName($method)) {
                    throw new Exception("Invalid controller or method name");
                }
                
                // Include controller file
                $controllerFile = "controllers/{$controllerName}.php";
                if (!file_exists($controllerFile)) {
                    throw new Exception("Controller file not found: {$controllerFile}");
                }
                
                require_once $controllerFile;
                
                // Instantiate controller
                if (!class_exists($controllerName)) {
                    throw new Exception("Controller class not found: {$controllerName}");
                }
                
                $controller = new $controllerName();
                
                // Call method
                if (!method_exists($controller, $method)) {
                    throw new Exception("Method not found: {$controllerName}::{$method}");
                }
                
                return $controller->$method($params);
            }
        }
        
        throw new Exception("Invalid route handler: " . print_r($handler, true));
    }
    
    /**
     * Validate controller name to prevent path traversal
     */
    private function isValidControllerName($name) {
        // Only allow alphanumeric characters and underscores
        return preg_match('/^[a-zA-Z_][a-zA-Z0-9_]*$/', $name) && !strpos($name, '..');
    }
    
    /**
     * Validate method name to prevent calling magic methods
     */
    private function isValidMethodName($name) {
        // Don't allow magic methods or methods starting with underscore
        return preg_match('/^[a-zA-Z][a-zA-Z0-9_]*$/', $name) && substr($name, 0, 2) !== '__';
    }
    
    /**
     * Handle 404 errors
     */
    private function handle404($method, $path) {
        http_response_code(404);
        
        // Log 404 for potential reconnaissance attempts
        logSecurityEvent('404_not_found', [
            'method' => $method,
            'path' => $path,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? ''
        ]);
        
        if (DEBUG_MODE) {
            echo "<h1>404 - Route Not Found</h1>";
            echo "<p><strong>Method:</strong> " . htmlspecialchars($method) . "</p>";
            echo "<p><strong>Path:</strong> " . htmlspecialchars($path) . "</p>";
            echo "<h3>Available Routes:</h3>";
            echo "<ul>";
            foreach ($this->routes as $route) {
                echo "<li>" . htmlspecialchars($route['method'] . ' ' . $route['pattern']) . "</li>";
            }
            echo "</ul>";
        } else {
            echo "<h1>Page Not Found</h1>";
            echo "<p>The requested page could not be found.</p>";
        }
        exit;
    }
    
    /**
     * Get current route information
     */
    public function getCurrentRoute() {
        return $this->currentRoute;
    }
    
    /**
     * Generate URL from route pattern and parameters
     */
    public function url($pattern, $params = []) {
        $url = $pattern;
        
        foreach ($params as $key => $value) {
            $url = str_replace('{' . $key . '}', $value, $url);
        }
        
        return APP_URL . $url;
    }
    
    /**
     * Get all registered routes (for debugging)
     */
    public function getRoutes() {
        return $this->routes;
    }
}

/**
 * Example Middleware Classes
 * These demonstrate common middleware patterns used in web applications
 */

/**
 * Authentication Middleware
 */
class AuthMiddleware {
    public function handle($params) {
        session_start();
        
        if (!isset($_SESSION['authenticated']) || !$_SESSION['authenticated']) {
            logSecurityEvent('unauthorized_access_attempt', [
                'route' => $_SERVER['REQUEST_URI'],
                'params' => $params
            ]);
            
            http_response_code(401);
            if (DEBUG_MODE) {
                die("Authentication required for this route");
            } else {
                die("Access denied");
            }
        }
        
        // Log successful authentication check
        if (DEBUG_MODE) {
            error_log("AuthMiddleware: User authenticated");
        }
    }
}

/**
 * Admin Role Middleware
 */
class AdminMiddleware {
    public function handle($params) {
        session_start();
        
        if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
            logSecurityEvent('unauthorized_admin_access', [
                'user_id' => $_SESSION['user_id'] ?? null,
                'route' => $_SERVER['REQUEST_URI'],
                'params' => $params
            ]);
            
            http_response_code(403);
            die("Admin access required");
        }
    }
}

/**
 * CSRF Protection Middleware
 */
class CSRFMiddleware {
    public function handle($params) {
        // Only check CSRF for state-changing methods
        if (in_array($_SERVER['REQUEST_METHOD'], ['POST', 'PUT', 'DELETE', 'PATCH'])) {
            $token = $_POST['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
            
            if (!validateCSRFToken($token)) {
                logSecurityEvent('csrf_validation_failed', [
                    'route' => $_SERVER['REQUEST_URI'],
                    'token_provided' => !empty($token),
                    'params' => $params
                ]);
                
                http_response_code(403);
                die("CSRF token validation failed");
            }
        }
    }
}

/**
 * Rate Limiting Middleware
 */
class RateLimitMiddleware {
    public function handle($params) {
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        
        if (!checkRateLimit($ip)) {
            logSecurityEvent('rate_limit_exceeded', [
                'ip' => $ip,
                'route' => $_SERVER['REQUEST_URI']
            ]);
            
            http_response_code(429);
            header('Retry-After: 3600');
            die("Rate limit exceeded. Try again later.");
        }
    }
}

/**
 * LEARNING NOTES FOR BUG BOUNTY HUNTERS:
 * 
 * 1. Route Parameter Injection:
 *    - Test for path traversal in route parameters
 *    - Try injecting special characters in {id} parameters
 *    - Test for SQL injection if parameters go to database
 * 
 * 2. HTTP Method Override:
 *    - Try different HTTP methods on the same endpoint
 *    - Look for method override headers (X-HTTP-Method-Override)
 *    - Test for privilege escalation through method changes
 * 
 * 3. Middleware Bypass:
 *    - Test if middleware applies to all required routes
 *    - Try accessing routes with different case variations
 *    - Test for Unicode normalization issues
 * 
 * 4. Route Discovery:
 *    - Look for commented routes in source code
 *    - Test for debug/development routes
 *    - Use directory brute forcing tools
 * 
 * 5. Common Vulnerabilities:
 *    - Mass assignment through parameter manipulation
 *    - Insecure direct object references in route parameters
 *    - Authentication/authorization bypasses
 *    - CSRF protection bypasses
 */
?>