<?php
/**
 * HomeController - Main Controller for Bug Bounty Learning
 * 
 * This controller demonstrates:
 * 1. Request handling and HTTP workflow
 * 2. Database interaction (secure and vulnerable)
 * 3. Session management
 * 4. Template rendering
 * 5. Input validation and sanitization
 * 6. Error handling
 * 7. Security vulnerabilities for learning
 */

class HomeController {
    private $db;
    private $session;
    private $template;
    
    public function __construct() {
        $this->db = new Database();
        $this->session = new Session();
        $this->template = new Template();
    }
    
    /**
     * Main index page - demonstrates HTTP workflow
     */
    public function index($params = []) {
        try {
            // Step 1: Log the request for educational purposes
            if (DEBUG_MODE) {
                error_log("HomeController::index called with params: " . json_encode($params));
            }
            
            // Step 2: Gather data for the view
            $data = $this->gatherHomePageData();
            
            // Step 3: Handle any flash messages
            $data['flash_messages'] = $this->session->getAllFlash();
            
            // Step 4: Add HTTP request information for learning
            $data['http_info'] = $this->getHttpRequestInfo();
            
            // Step 5: Add CSRF token for forms
            $data['csrf_token'] = generateCSRFToken();
            
            // Step 6: Render the template
            $this->template->setLayout('main');
            echo $this->template->render('home/index', $data);
            
        } catch (Exception $e) {
            $this->handleError($e, 'Failed to load home page');
        }
    }
    
    /**
     * HTTP information display page
     */
    public function httpInfo($params = []) {
        $data = [
            'title' => 'HTTP Request Information',
            'http_details' => $this->getDetailedHttpInfo(),
            'headers' => getallheaders(),
            'server_vars' => $_SERVER,
            'session_info' => $this->session->getSessionInfo(),
            'database_info' => $this->db->getConnectionInfo()
        ];
        
        // Filter sensitive information in production
        if (!DEBUG_MODE) {
            unset($data['server_vars']['HTTP_AUTHORIZATION']);
            unset($data['database_info']['username']);
        }
        
        $this->template->setLayout('main');
        echo $this->template->render('home/http-info', $data);
    }
    
    /**
     * SQL Injection demonstration
     */
    public function sqlInjectionDemo($params = []) {
        $searchTerm = $_GET['search'] ?? '';
        $mode = $_GET['mode'] ?? 'secure';
        
        $data = [
            'title' => 'SQL Injection Demonstration',
            'search_term' => $searchTerm,
            'mode' => $mode,
            'results' => [],
            'error' => null
        ];
        
        if (!empty($searchTerm)) {
            try {
                if ($mode === 'vulnerable' && DEBUG_MODE) {
                    // Vulnerable search - for educational purposes only
                    $vulnerableDb = new Database(false);
                    $results = $vulnerableDb->vulnerableUserSearch($searchTerm);
                    $data['results'] = $results ? $results->fetchAll() : [];
                    $data['warning'] = 'This query is vulnerable to SQL injection!';
                } else {
                    // Secure search
                    $data['results'] = $this->db->select('users', 'id, username, email', [], ['limit' => 10]);
                    $data['info'] = 'This query uses prepared statements and is safe.';
                }
            } catch (Exception $e) {
                $data['error'] = DEBUG_MODE ? $e->getMessage() : 'Search failed';
                logSecurityEvent('sql_injection_attempt', [
                    'search_term' => $searchTerm,
                    'mode' => $mode,
                    'error' => $e->getMessage()
                ]);
            }
        }
        
        $data['payloads'] = $this->getSqlInjectionPayloads();
        
        $this->template->setLayout('main');
        echo $this->template->render('home/sql-injection', $data);
    }
    
    /**
     * XSS demonstration
     */
    public function xssDemo($params = []) {
        $userInput = $_GET['input'] ?? '';
        $context = $_GET['context'] ?? 'html';
        
        $data = [
            'title' => 'XSS (Cross-Site Scripting) Demonstration',
            'user_input' => $userInput,
            'context' => $context,
            'safe_output' => htmlspecialchars($userInput, ENT_QUOTES, 'UTF-8'),
            'unsafe_output' => $userInput, // Deliberately unsafe for demo
            'contexts' => ['html', 'attribute', 'javascript', 'css', 'url'],
            'payloads' => $this->getXssPayloads()
        ];
        
        // Log XSS attempt for analysis
        if (!empty($userInput)) {
            logSecurityEvent('xss_test', [
                'input' => $userInput,
                'context' => $context
            ]);
        }
        
        $this->template->setLayout('main');
        echo $this->template->render('home/xss-demo', $data);
    }
    
    /**
     * CSRF demonstration
     */
    public function csrfDemo($params = []) {
        $data = [
            'title' => 'CSRF (Cross-Site Request Forgery) Demonstration',
            'csrf_token' => generateCSRFToken(),
            'form_submitted' => false,
            'csrf_valid' => false
        ];
        
        // Handle form submission
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $data['form_submitted'] = true;
            $data['submitted_data'] = $_POST;
            
            // Check CSRF token
            $submittedToken = $_POST['csrf_token'] ?? '';
            $data['csrf_valid'] = validateCSRFToken($submittedToken);
            
            if ($data['csrf_valid']) {
                $this->session->flash('success', 'Form submitted successfully with valid CSRF token!');
            } else {
                $this->session->flash('error', 'CSRF token validation failed!');
                logSecurityEvent('csrf_validation_failed', [
                    'submitted_token' => $submittedToken,
                    'expected_token' => $_SESSION['csrf_token'] ?? 'none'
                ]);
            }
        }
        
        $this->template->setLayout('main');
        echo $this->template->render('home/csrf-demo', $data);
    }
    
    /**
     * Session management demonstration
     */
    public function sessionDemo($params = []) {
        $action = $_GET['action'] ?? '';
        
        $data = [
            'title' => 'Session Management Demonstration',
            'session_info' => $this->session->getSessionInfo(),
            'is_authenticated' => $this->session->isAuthenticated(),
            'user_id' => $this->session->getUserId()
        ];
        
        // Handle session actions
        switch ($action) {
            case 'login':
                $this->session->login('demo_user_' . time(), [
                    'username' => 'Demo User',
                    'role' => 'user'
                ]);
                $this->session->flash('success', 'Logged in successfully!');
                break;
                
            case 'logout':
                $this->session->logout();
                $this->session->flash('info', 'Logged out successfully!');
                break;
                
            case 'regenerate':
                $this->session->regenerateId();
                $this->session->flash('info', 'Session ID regenerated!');
                break;
                
            case 'test_fixation':
                if (DEBUG_MODE) {
                    // Demonstrate session fixation vulnerability
                    $insecureSession = new Session(false);
                    $insecureSession->insecureLogin('vulnerable_user');
                    $this->session->flash('warning', 'Vulnerable login performed (no session regeneration)!');
                }
                break;
        }
        
        $data['session_info'] = $this->session->getSessionInfo();
        $data['is_authenticated'] = $this->session->isAuthenticated();
        
        $this->template->setLayout('main');
        echo $this->template->render('home/session-demo', $data);
    }
    
    /**
     * API endpoint - JSON response example
     */
    public function apiUsers($params = []) {
        try {
            // Check authentication for API access
            if (!$this->session->isAuthenticated()) {
                jsonResponse(['error' => 'Authentication required'], 401);
            }
            
            // Get users with pagination
            $limit = (int)($_GET['limit'] ?? 10);
            $offset = (int)($_GET['offset'] ?? 0);
            
            // Validate pagination parameters
            $limit = max(1, min(100, $limit)); // Between 1 and 100
            $offset = max(0, $offset);
            
            $users = $this->db->select('users', 'id, username, email, role, created_at', 
                                     ['is_active' => 1], 
                                     ['limit' => $limit, 'order_by' => 'created_at DESC']);
            
            jsonResponse([
                'status' => 'success',
                'data' => $users,
                'pagination' => [
                    'limit' => $limit,
                    'offset' => $offset,
                    'total' => count($users)
                ]
            ]);
            
        } catch (Exception $e) {
            logSecurityEvent('api_error', [
                'endpoint' => 'users',
                'error' => $e->getMessage()
            ]);
            
            jsonResponse(['error' => 'Internal server error'], 500);
        }
    }
    
    /**
     * API login endpoint
     */
    public function apiLogin($params = []) {
        try {
            $username = $_POST['username'] ?? '';
            $password = $_POST['password'] ?? '';
            
            if (empty($username) || empty($password)) {
                jsonResponse(['error' => 'Username and password required'], 400);
            }
            
            // Attempt login
            $user = $this->db->getUserByUsername($username);
            
            if ($user && password_verify($password, $user['password'])) {
                $this->session->login($user['id'], [
                    'username' => $user['username'],
                    'role' => $user['role']
                ]);
                
                jsonResponse([
                    'status' => 'success',
                    'message' => 'Login successful',
                    'user' => [
                        'id' => $user['id'],
                        'username' => $user['username'],
                        'role' => $user['role']
                    ]
                ]);
            } else {
                // Log failed login attempt
                logSecurityEvent('login_failed', [
                    'username' => $username,
                    'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
                ]);
                
                jsonResponse(['error' => 'Invalid credentials'], 401);
            }
            
        } catch (Exception $e) {
            logSecurityEvent('api_login_error', [
                'error' => $e->getMessage()
            ]);
            
            jsonResponse(['error' => 'Login failed'], 500);
        }
    }
    
    /**
     * File operations demonstration
     */
    public function fileList($params = []) {
        $data = [
            'title' => 'File Operations',
            'files' => [],
            'upload_path' => UPLOAD_PATH
        ];
        
        // List uploaded files
        if (is_dir(UPLOAD_PATH)) {
            $files = array_diff(scandir(UPLOAD_PATH), ['.', '..']);
            foreach ($files as $file) {
                $filePath = UPLOAD_PATH . '/' . $file;
                if (is_file($filePath)) {
                    $data['files'][] = [
                        'name' => $file,
                        'size' => filesize($filePath),
                        'modified' => filemtime($filePath),
                        'type' => mime_content_type($filePath)
                    ];
                }
            }
        }
        
        $this->template->setLayout('main');
        echo $this->template->render('home/files', $data);
    }
    
    /**
     * File upload handling
     */
    public function fileUpload($params = []) {
        try {
            if (!isset($_FILES['file'])) {
                throw new Exception('No file uploaded');
            }
            
            $file = $_FILES['file'];
            $validation = validateFileUpload($file);
            
            if ($validation !== true) {
                throw new Exception(implode(', ', $validation));
            }
            
            // Generate secure filename
            $extension = pathinfo($file['name'], PATHINFO_EXTENSION);
            $filename = uniqid('upload_') . '.' . $extension;
            $destination = UPLOAD_PATH . '/' . $filename;
            
            if (move_uploaded_file($file['tmp_name'], $destination)) {
                $this->session->flash('success', 'File uploaded successfully: ' . $filename);
                
                logSecurityEvent('file_uploaded', [
                    'filename' => $filename,
                    'original_name' => $file['name'],
                    'size' => $file['size'],
                    'type' => $file['type']
                ]);
            } else {
                throw new Exception('Failed to move uploaded file');
            }
            
        } catch (Exception $e) {
            $this->session->flash('error', 'Upload failed: ' . $e->getMessage());
        }
        
        redirectTo('/files');
    }
    
    /**
     * Admin dashboard (requires authentication)
     */
    public function admin($params = []) {
        // Check authentication
        if (!$this->session->isAuthenticated()) {
            $this->session->flash('error', 'Please log in to access admin area');
            redirectTo('/');
        }
        
        $data = [
            'title' => 'Admin Dashboard',
            'user_id' => $this->session->getUserId(),
            'stats' => $this->db->getStats(),
            'recent_logs' => $this->getRecentSecurityLogs()
        ];
        
        $this->template->setLayout('main');
        echo $this->template->render('home/admin', $data);
    }
    
    /**
     * Admin users management
     */
    public function adminUsers($params = []) {
        // Check admin role
        if (!$this->session->isAuthenticated() || $this->session->get('role') !== 'admin') {
            $this->session->flash('error', 'Admin access required');
            redirectTo('/');
        }
        
        $data = [
            'title' => 'User Management',
            'users' => $this->db->select('users', 'id, username, email, role, created_at, is_active')
        ];
        
        $this->template->setLayout('main');
        echo $this->template->render('home/admin-users', $data);
    }
    
    /**
     * Helper method to gather home page data
     */
    private function gatherHomePageData() {
        $data = [
            'title' => 'PHP Bug Bounty Learning Environment',
            'app_name' => APP_NAME,
            'app_version' => APP_VERSION,
            'debug_mode' => DEBUG_MODE,
            'session_active' => $this->session->isAuthenticated(),
            'user_id' => $this->session->getUserId()
        ];
        
        // Get database statistics
        try {
            $data['stats'] = $this->db->getStats();
        } catch (Exception $e) {
            $data['stats'] = ['error' => 'Unable to fetch statistics'];
        }
        
        // Get recent posts
        try {
            $data['recent_posts'] = $this->db->getPosts(5, 0);
        } catch (Exception $e) {
            $data['recent_posts'] = [];
        }
        
        return $data;
    }
    
    /**
     * Get HTTP request information
     */
    private function getHttpRequestInfo() {
        return [
            'method' => $_SERVER['REQUEST_METHOD'],
            'uri' => $_SERVER['REQUEST_URI'],
            'protocol' => $_SERVER['SERVER_PROTOCOL'] ?? 'HTTP/1.1',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'remote_addr' => $_SERVER['REMOTE_ADDR'] ?? '',
            'query_string' => $_SERVER['QUERY_STRING'] ?? '',
            'content_type' => $_SERVER['CONTENT_TYPE'] ?? '',
            'content_length' => $_SERVER['CONTENT_LENGTH'] ?? 0,
            'timestamp' => date('Y-m-d H:i:s')
        ];
    }
    
    /**
     * Get detailed HTTP information
     */
    private function getDetailedHttpInfo() {
        return [
            'request_method' => $_SERVER['REQUEST_METHOD'],
            'request_uri' => $_SERVER['REQUEST_URI'],
            'server_protocol' => $_SERVER['SERVER_PROTOCOL'] ?? 'HTTP/1.1',
            'server_name' => $_SERVER['SERVER_NAME'] ?? '',
            'server_port' => $_SERVER['SERVER_PORT'] ?? '',
            'https' => isset($_SERVER['HTTPS']) ? 'on' : 'off',
            'document_root' => $_SERVER['DOCUMENT_ROOT'] ?? '',
            'script_name' => $_SERVER['SCRIPT_NAME'] ?? '',
            'path_info' => $_SERVER['PATH_INFO'] ?? '',
            'query_string' => $_SERVER['QUERY_STRING'] ?? '',
            'remote_addr' => $_SERVER['REMOTE_ADDR'] ?? '',
            'remote_host' => $_SERVER['REMOTE_HOST'] ?? '',
            'remote_user' => $_SERVER['REMOTE_USER'] ?? '',
            'request_time' => $_SERVER['REQUEST_TIME'] ?? 0,
            'request_time_float' => $_SERVER['REQUEST_TIME_FLOAT'] ?? 0.0
        ];
    }
    
    /**
     * Get SQL injection payloads for educational purposes
     */
    private function getSqlInjectionPayloads() {
        return [
            "Basic Tests" => [
                "' OR '1'='1",
                "' OR 1=1--",
                "admin'--",
                "' OR 'a'='a"
            ],
            "Union-based" => [
                "' UNION SELECT 1,2,3--",
                "' UNION SELECT username,password FROM users--",
                "' UNION SELECT @@version,2,3--"
            ],
            "Boolean-based Blind" => [
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND 'a'='a'--",
                "' AND 'a'='b'--"
            ],
            "Time-based Blind" => [
                "' AND SLEEP(5)--",
                "'; WAITFOR DELAY '00:00:05'--",
                "' OR IF(1=1,SLEEP(5),0)--"
            ]
        ];
    }
    
    /**
     * Get XSS payloads for educational purposes
     */
    private function getXssPayloads() {
        return [
            "Basic XSS" => [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')"
            ],
            "Event Handlers" => [
                "<input onfocus=alert('XSS') autofocus>",
                "<select onfocus=alert('XSS') autofocus>",
                "<textarea onfocus=alert('XSS') autofocus>",
                "<button onclick=alert('XSS')>Click</button>"
            ],
            "Encoding Bypasses" => [
                "&#60;script&#62;alert('XSS')&#60;/script&#62;",
                "%3Cscript%3Ealert('XSS')%3C/script%3E",
                "\\u003cscript\\u003ealert('XSS')\\u003c/script\\u003e"
            ]
        ];
    }
    
    /**
     * Get recent security logs
     */
    private function getRecentSecurityLogs() {
        try {
            return $this->db->select('security_logs', '*', [], ['order_by' => 'created_at DESC', 'limit' => 10]);
        } catch (Exception $e) {
            return [];
        }
    }
    
    /**
     * Error handling
     */
    private function handleError($exception, $userMessage = 'An error occurred') {
        // Log the error
        error_log("HomeController Error: " . $exception->getMessage());
        
        // Log security event if it might be an attack
        logSecurityEvent('controller_error', [
            'message' => $exception->getMessage(),
            'file' => $exception->getFile(),
            'line' => $exception->getLine()
        ]);
        
        if (DEBUG_MODE) {
            // Show detailed error in debug mode
            echo "<h1>Error</h1>";
            echo "<p>" . htmlspecialchars($exception->getMessage()) . "</p>";
            echo "<pre>" . htmlspecialchars($exception->getTraceAsString()) . "</pre>";
        } else {
            // Show user-friendly error in production
            $this->template->setLayout('main');
            echo $this->template->render('errors/500', [
                'title' => 'Error',
                'message' => $userMessage
            ]);
        }
    }
}

/**
 * LEARNING NOTES FOR BUG BOUNTY HUNTERS:
 * 
 * 1. Controller Analysis:
 *    - Map all controller methods and their parameters
 *    - Test input validation on each method
 *    - Look for privilege escalation opportunities
 *    - Check error handling and information disclosure
 * 
 * 2. Common Vulnerabilities in Controllers:
 *    - Missing authentication/authorization checks
 *    - Insecure direct object references
 *    - Mass assignment vulnerabilities
 *    - Command injection in system calls
 *    - Path traversal in file operations
 * 
 * 3. Testing Methodology:
 *    - Test each endpoint with different HTTP methods
 *    - Try accessing admin functions without proper authentication
 *    - Test file upload functionality for malicious files
 *    - Check API endpoints for proper validation
 *    - Test error conditions to reveal information
 * 
 * 4. Security Patterns to Look For:
 *    - Consistent authentication checks
 *    - Proper input validation and sanitization
 *    - CSRF protection implementation
 *    - Rate limiting on sensitive operations
 *    - Secure error handling
 * 
 * 5. Tools for Testing:
 *    - Burp Suite for request manipulation
 *    - OWASP ZAP for automated scanning
 *    - Custom scripts for specific vulnerabilities
 *    - Browser developer tools for client-side analysis
 */
?>