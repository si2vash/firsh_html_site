<?php
/**
 * Session Management Class - Secure and Insecure Session Handling
 * 
 * This class demonstrates:
 * 1. Secure session lifecycle management
 * 2. Session fixation prevention
 * 3. Session hijacking prevention
 * 4. Secure cookie handling
 * 5. Flash data and temporary session data
 * 6. Common session vulnerabilities and protections
 */

class Session {
    private $sessionStarted = false;
    private $secureMode = true;
    
    public function __construct($secureMode = true) {
        $this->secureMode = $secureMode;
        $this->configureSession();
    }
    
    /**
     * Configure session security settings
     */
    private function configureSession() {
        if (!$this->sessionStarted && session_status() !== PHP_SESSION_ACTIVE) {
            if ($this->secureMode) {
                // Secure session configuration
                ini_set('session.cookie_httponly', 1); // Prevent XSS access to session cookie
                ini_set('session.cookie_secure', 0); // Set to 1 for HTTPS only (0 for local development)
                ini_set('session.use_strict_mode', 1); // Reject uninitialized session IDs
                ini_set('session.cookie_samesite', 'Lax'); // CSRF protection
                ini_set('session.use_only_cookies', 1); // Prevent session ID in URL
                ini_set('session.entropy_file', '/dev/urandom'); // Strong entropy source
                ini_set('session.entropy_length', 32);
                ini_set('session.hash_function', 'sha256'); // Strong hash function
            } else {
                // Insecure configuration (for vulnerability demonstration)
                ini_set('session.cookie_httponly', 0); // Vulnerable to XSS
                ini_set('session.cookie_secure', 0);
                ini_set('session.use_strict_mode', 0); // Accept any session ID
                ini_set('session.use_only_cookies', 0); // Allow session ID in URL
            }
            
            // Set session name
            session_name('PHPSESSID_BUGBOUNTY');
            
            // Set session lifetime
            ini_set('session.gc_maxlifetime', SESSION_TIMEOUT);
            ini_set('session.cookie_lifetime', 0); // Session cookie
            
            session_start();
            $this->sessionStarted = true;
            
            // Initialize session security
            if ($this->secureMode) {
                $this->initializeSecureSession();
            }
        }
    }
    
    /**
     * Initialize secure session with additional protections
     */
    private function initializeSecureSession() {
        // Check for session hijacking
        if ($this->isSessionHijacked()) {
            $this->destroySession();
            $this->regenerateId();
            logSecurityEvent('session_hijacking_detected', [
                'old_session_id' => session_id(),
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
                'ip_address' => $_SERVER['REMOTE_ADDR'] ?? ''
            ]);
        }
        
        // Check session timeout
        if ($this->isSessionExpired()) {
            $this->destroySession();
            logSecurityEvent('session_expired', [
                'session_id' => session_id(),
                'last_activity' => $_SESSION['last_activity'] ?? 'unknown'
            ]);
        }
        
        // Update session fingerprint
        $this->updateSessionFingerprint();
        
        // Update last activity
        $_SESSION['last_activity'] = time();
    }
    
    /**
     * Check if session is hijacked
     */
    private function isSessionHijacked() {
        if (!isset($_SESSION['session_fingerprint'])) {
            return false; // First time, not hijacked
        }
        
        $currentFingerprint = $this->generateSessionFingerprint();
        return $_SESSION['session_fingerprint'] !== $currentFingerprint;
    }
    
    /**
     * Check if session is expired
     */
    private function isSessionExpired() {
        if (!isset($_SESSION['last_activity'])) {
            return false; // First time, not expired
        }
        
        return (time() - $_SESSION['last_activity']) > SESSION_TIMEOUT;
    }
    
    /**
     * Generate session fingerprint for hijacking detection
     */
    private function generateSessionFingerprint() {
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $acceptLanguage = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '';
        $acceptEncoding = $_SERVER['HTTP_ACCEPT_ENCODING'] ?? '';
        
        // Include IP for stricter security (might cause issues with mobile users)
        $ipAddress = $_SERVER['REMOTE_ADDR'] ?? '';
        
        return hash('sha256', $userAgent . $acceptLanguage . $acceptEncoding . $ipAddress . SECRET_KEY);
    }
    
    /**
     * Update session fingerprint
     */
    private function updateSessionFingerprint() {
        $_SESSION['session_fingerprint'] = $this->generateSessionFingerprint();
    }
    
    /**
     * Regenerate session ID (prevents session fixation)
     */
    public function regenerateId($deleteOld = true) {
        if ($this->sessionStarted) {
            $oldSessionId = session_id();
            session_regenerate_id($deleteOld);
            
            if (DEBUG_MODE) {
                error_log("Session ID regenerated: $oldSessionId -> " . session_id());
            }
            
            logSecurityEvent('session_id_regenerated', [
                'old_id' => $oldSessionId,
                'new_id' => session_id()
            ]);
        }
    }
    
    /**
     * Set session data
     */
    public function set($key, $value) {
        $this->ensureStarted();
        $_SESSION[$key] = $value;
        
        if (DEBUG_MODE) {
            error_log("Session data set: $key");
        }
    }
    
    /**
     * Get session data
     */
    public function get($key, $default = null) {
        $this->ensureStarted();
        return $_SESSION[$key] ?? $default;
    }
    
    /**
     * Check if session key exists
     */
    public function has($key) {
        $this->ensureStarted();
        return isset($_SESSION[$key]);
    }
    
    /**
     * Remove session data
     */
    public function remove($key) {
        $this->ensureStarted();
        if (isset($_SESSION[$key])) {
            unset($_SESSION[$key]);
            if (DEBUG_MODE) {
                error_log("Session data removed: $key");
            }
        }
    }
    
    /**
     * Flash data - set data that will be available for the next request only
     */
    public function flash($key, $value) {
        $this->ensureStarted();
        $_SESSION['flash'][$key] = $value;
    }
    
    /**
     * Get flash data
     */
    public function getFlash($key, $default = null) {
        $this->ensureStarted();
        $value = $_SESSION['flash'][$key] ?? $default;
        unset($_SESSION['flash'][$key]);
        return $value;
    }
    
    /**
     * Get all flash data and clear it
     */
    public function getAllFlash() {
        $this->ensureStarted();
        $flash = $_SESSION['flash'] ?? [];
        unset($_SESSION['flash']);
        return $flash;
    }
    
    /**
     * Authentication helpers
     */
    public function login($userId, $userData = []) {
        $this->ensureStarted();
        
        // Regenerate session ID to prevent session fixation
        $this->regenerateId();
        
        // Set authentication data
        $_SESSION['authenticated'] = true;
        $_SESSION['user_id'] = $userId;
        $_SESSION['login_time'] = time();
        
        // Set additional user data
        foreach ($userData as $key => $value) {
            $_SESSION[$key] = $value;
        }
        
        logSecurityEvent('user_login', [
            'user_id' => $userId,
            'session_id' => session_id(),
            'ip_address' => $_SERVER['REMOTE_ADDR'] ?? ''
        ]);
        
        if (DEBUG_MODE) {
            error_log("User logged in: $userId");
        }
    }
    
    /**
     * Check if user is authenticated
     */
    public function isAuthenticated() {
        $this->ensureStarted();
        return $_SESSION['authenticated'] ?? false;
    }
    
    /**
     * Get current user ID
     */
    public function getUserId() {
        $this->ensureStarted();
        return $_SESSION['user_id'] ?? null;
    }
    
    /**
     * Logout user
     */
    public function logout() {
        $this->ensureStarted();
        
        $userId = $this->getUserId();
        
        logSecurityEvent('user_logout', [
            'user_id' => $userId,
            'session_id' => session_id()
        ]);
        
        // Clear all session data
        $this->destroySession();
        
        if (DEBUG_MODE) {
            error_log("User logged out: $userId");
        }
    }
    
    /**
     * Destroy session completely
     */
    public function destroySession() {
        $this->ensureStarted();
        
        // Clear session data
        $_SESSION = [];
        
        // Delete session cookie
        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000,
                $params['path'], $params['domain'],
                $params['secure'], $params['httponly']
            );
        }
        
        // Destroy session
        session_destroy();
        $this->sessionStarted = false;
        
        if (DEBUG_MODE) {
            error_log("Session destroyed");
        }
    }
    
    /**
     * Get session ID
     */
    public function getId() {
        $this->ensureStarted();
        return session_id();
    }
    
    /**
     * Get all session data (for debugging)
     */
    public function getAll() {
        $this->ensureStarted();
        return $_SESSION;
    }
    
    /**
     * Ensure session is started
     */
    private function ensureStarted() {
        if (!$this->sessionStarted) {
            $this->configureSession();
        }
    }
    
    /**
     * Get session info for debugging
     */
    public function getSessionInfo() {
        return [
            'session_id' => session_id(),
            'session_status' => session_status(),
            'session_name' => session_name(),
            'cookie_params' => session_get_cookie_params(),
            'session_data' => $_SESSION ?? [],
            'secure_mode' => $this->secureMode,
            'last_activity' => $_SESSION['last_activity'] ?? null,
            'fingerprint' => $_SESSION['session_fingerprint'] ?? null
        ];
    }
    
    /**
     * VULNERABLE METHODS FOR LEARNING
     * These demonstrate common session vulnerabilities
     */
    
    /**
     * Insecure login (vulnerable to session fixation)
     */
    public function insecureLogin($userId, $userData = []) {
        $this->ensureStarted();
        
        // WARNING: No session ID regeneration - vulnerable to session fixation
        $_SESSION['authenticated'] = true;
        $_SESSION['user_id'] = $userId;
        
        foreach ($userData as $key => $value) {
            $_SESSION[$key] = $value;
        }
        
        if (DEBUG_MODE) {
            error_log("INSECURE login: $userId (no session regeneration)");
        }
    }
    
    /**
     * Store sensitive data without encryption
     */
    public function storeSensitiveData($key, $sensitiveData) {
        // WARNING: Storing sensitive data in plain text in session
        $_SESSION[$key] = $sensitiveData;
    }
    
    /**
     * Get session without hijacking protection
     */
    public function getInsecure($key, $default = null) {
        // WARNING: No session hijacking protection
        return $_SESSION[$key] ?? $default;
    }
}

/**
 * Global Session Helper Functions
 */

/**
 * Quick session access
 */
function session($key = null, $value = null) {
    static $sessionInstance = null;
    
    if ($sessionInstance === null) {
        $sessionInstance = new Session();
    }
    
    if ($key === null) {
        return $sessionInstance;
    }
    
    if ($value !== null) {
        return $sessionInstance->set($key, $value);
    }
    
    return $sessionInstance->get($key);
}

/**
 * Flash message helpers
 */
function flash($key, $value = null) {
    $session = session();
    
    if ($value !== null) {
        return $session->flash($key, $value);
    }
    
    return $session->getFlash($key);
}

/**
 * Authentication helpers
 */
function auth() {
    return session();
}

function isLoggedIn() {
    return session()->isAuthenticated();
}

function userId() {
    return session()->getUserId();
}

/**
 * CSRF token helpers
 */
function setCSRFToken() {
    session()->set('csrf_token', generateCSRFToken());
}

function getCSRFToken() {
    return session()->get('csrf_token');
}

/**
 * Session Security Testing Functions
 */

/**
 * Test session fixation vulnerability
 */
function testSessionFixation() {
    echo "<div class='vulnerability-test'>";
    echo "<h3>Session Fixation Test</h3>";
    echo "<p><strong>Current Session ID:</strong> " . session_id() . "</p>";
    
    // Demonstrate fixation
    echo "<p>Try accessing this page with ?PHPSESSID=malicious_session_id</p>";
    echo "<p>In vulnerable applications, the session ID wouldn't change after login.</p>";
    
    echo "</div>";
}

/**
 * Test session hijacking detection
 */
function testSessionHijacking() {
    echo "<div class='vulnerability-test'>";
    echo "<h3>Session Hijacking Detection Test</h3>";
    
    $session = new Session();
    $info = $session->getSessionInfo();
    
    echo "<p><strong>Current Fingerprint:</strong> " . ($info['fingerprint'] ?? 'Not set') . "</p>";
    echo "<p><strong>User Agent:</strong> " . htmlspecialchars($_SERVER['HTTP_USER_AGENT'] ?? '') . "</p>";
    echo "<p><strong>IP Address:</strong> " . ($_SERVER['REMOTE_ADDR'] ?? '') . "</p>";
    
    echo "<p>Change your user agent and refresh to test hijacking detection.</p>";
    echo "</div>";
}

/**
 * Session security demonstration
 */
function sessionSecurityDemo() {
    echo "<div class='security-demo'>";
    echo "<h3>Session Security Demonstration</h3>";
    
    $secureSession = new Session(true);
    $insecureSession = new Session(false);
    
    echo "<h4>Secure Session Configuration:</h4>";
    echo "<ul>";
    echo "<li>HttpOnly cookies: " . (ini_get('session.cookie_httponly') ? 'Yes' : 'No') . "</li>";
    echo "<li>Secure cookies: " . (ini_get('session.cookie_secure') ? 'Yes' : 'No') . "</li>";
    echo "<li>Strict mode: " . (ini_get('session.use_strict_mode') ? 'Yes' : 'No') . "</li>";
    echo "<li>Use only cookies: " . (ini_get('session.use_only_cookies') ? 'Yes' : 'No') . "</li>";
    echo "</ul>";
    
    echo "<h4>Session Info:</h4>";
    echo "<pre>" . htmlspecialchars(json_encode($secureSession->getSessionInfo(), JSON_PRETTY_PRINT)) . "</pre>";
    
    echo "</div>";
}

/**
 * LEARNING NOTES FOR BUG BOUNTY HUNTERS:
 * 
 * 1. Session Fixation:
 *    - Test if session ID changes after login
 *    - Try setting session ID via URL parameter
 *    - Check if application accepts arbitrary session IDs
 * 
 * 2. Session Hijacking:
 *    - Test if sessions work from different IP addresses
 *    - Check if application validates user agent
 *    - Look for session tokens in URLs or logs
 * 
 * 3. Session Management Issues:
 *    - Test session timeout implementation
 *    - Check if logout properly destroys sessions
 *    - Look for concurrent session handling
 * 
 * 4. Cookie Security:
 *    - Check for HttpOnly flag on session cookies
 *    - Verify Secure flag for HTTPS
 *    - Test SameSite attribute for CSRF protection
 * 
 * 5. Common Testing Scenarios:
 *    - Login with one account, change session ID, try to access another account
 *    - Capture session token and use from different browser/IP
 *    - Test session persistence after browser close
 *    - Check for sensitive data in session storage
 * 
 * 6. Tools for Testing:
 *    - Burp Suite session handling rules
 *    - Browser developer tools for cookie inspection
 *    - Custom scripts for session manipulation
 */
?>