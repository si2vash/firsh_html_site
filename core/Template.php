<?php
/**
 * Template Engine - Secure and Insecure Rendering Demonstration
 * 
 * This class demonstrates:
 * 1. Template rendering with variable interpolation
 * 2. Secure output escaping vs insecure output
 * 3. Template inheritance and layouts
 * 4. Context-aware escaping
 * 5. Common XSS vulnerabilities and prevention
 */

class Template {
    private $viewPath;
    private $data = [];
    private $secureMode = true;
    private $layout = null;
    private $sections = [];
    private $currentSection = null;
    
    public function __construct($viewPath = null) {
        $this->viewPath = $viewPath ?: VIEW_PATH;
    }
    
    /**
     * Render a template with data
     */
    public function render($template, $data = [], $secure = true) {
        $this->secureMode = $secure;
        $this->data = array_merge($this->data, $data);
        
        // Log template rendering for debugging
        if (DEBUG_MODE) {
            error_log("Template rendering: $template (secure: " . ($secure ? 'yes' : 'no') . ")");
        }
        
        $templatePath = $this->getTemplatePath($template);
        
        if (!file_exists($templatePath)) {
            throw new Exception("Template not found: $template");
        }
        
        // Extract data as variables
        extract($this->data);
        
        // Start output buffering
        ob_start();
        
        // Include the template
        include $templatePath;
        
        $content = ob_get_clean();
        
        // If using layout, wrap content in layout
        if ($this->layout) {
            $layoutPath = $this->getTemplatePath("layouts/{$this->layout}");
            if (file_exists($layoutPath)) {
                $this->sections['content'] = $content;
                extract($this->data);
                ob_start();
                include $layoutPath;
                $content = ob_get_clean();
            }
        }
        
        return $content;
    }
    
    /**
     * Set the layout template
     */
    public function setLayout($layout) {
        $this->layout = $layout;
    }
    
    /**
     * Start a section (for layout inheritance)
     */
    public function section($name) {
        $this->currentSection = $name;
        ob_start();
    }
    
    /**
     * End a section
     */
    public function endSection() {
        if ($this->currentSection) {
            $this->sections[$this->currentSection] = ob_get_clean();
            $this->currentSection = null;
        }
    }
    
    /**
     * Yield section content (used in layouts)
     */
    public function yieldSection($name, $default = '') {
        return $this->sections[$name] ?? $default;
    }
    
    /**
     * Secure output - escapes HTML to prevent XSS
     */
    public function e($value, $encoding = 'UTF-8') {
        if ($this->secureMode) {
            return htmlspecialchars($value ?? '', ENT_QUOTES | ENT_HTML5, $encoding);
        } else {
            // Insecure mode - for vulnerability demonstration
            return $value;
        }
    }
    
    /**
     * Raw output - does not escape (vulnerable if used with user input)
     */
    public function raw($value) {
        return $value;
    }
    
    /**
     * Context-aware escaping for different contexts
     */
    public function escape($value, $context = 'html') {
        switch ($context) {
            case 'html':
                return htmlspecialchars($value ?? '', ENT_QUOTES | ENT_HTML5, 'UTF-8');
            
            case 'js':
                return json_encode($value, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP);
            
            case 'css':
                // Simple CSS escaping - in production use a proper CSS escaper
                return preg_replace('/[^a-zA-Z0-9\-_]/', '', $value ?? '');
            
            case 'url':
                return urlencode($value ?? '');
            
            case 'attr':
                return htmlspecialchars($value ?? '', ENT_QUOTES | ENT_HTML5, 'UTF-8');
            
            default:
                return htmlspecialchars($value ?? '', ENT_QUOTES | ENT_HTML5, 'UTF-8');
        }
    }
    
    /**
     * Include another template
     */
    public function include($template, $data = []) {
        $mergedData = array_merge($this->data, $data);
        return $this->render($template, $mergedData, $this->secureMode);
    }
    
    /**
     * Check if template exists
     */
    public function exists($template) {
        return file_exists($this->getTemplatePath($template));
    }
    
    /**
     * Get full template path
     */
    private function getTemplatePath($template) {
        // Security: Prevent path traversal
        $template = str_replace(['../', '..\\'], '', $template);
        
        // Add .php extension if not present
        if (!pathinfo($template, PATHINFO_EXTENSION)) {
            $template .= '.php';
        }
        
        return $this->viewPath . '/' . $template;
    }
    
    /**
     * Set template data
     */
    public function with($key, $value = null) {
        if (is_array($key)) {
            $this->data = array_merge($this->data, $key);
        } else {
            $this->data[$key] = $value;
        }
        return $this;
    }
    
    /**
     * Format date for display
     */
    public function formatDate($date, $format = 'Y-m-d H:i:s') {
        if ($date instanceof DateTime) {
            return $date->format($format);
        }
        
        $timestamp = is_numeric($date) ? $date : strtotime($date);
        return date($format, $timestamp);
    }
    
    /**
     * Truncate text
     */
    public function truncate($text, $length = 100, $suffix = '...') {
        if (strlen($text) <= $length) {
            return $text;
        }
        
        return substr($text, 0, $length) . $suffix;
    }
    
    /**
     * Generate CSRF token field for forms
     */
    public function csrfField() {
        $token = generateCSRFToken();
        return "<input type=\"hidden\" name=\"csrf_token\" value=\"" . $this->e($token) . "\">";
    }
    
    /**
     * Generate method field for HTTP method spoofing
     */
    public function methodField($method) {
        return "<input type=\"hidden\" name=\"_method\" value=\"" . $this->e(strtoupper($method)) . "\">";
    }
    
    /**
     * Generate URL
     */
    public function url($path = '') {
        return APP_URL . '/' . ltrim($path, '/');
    }
    
    /**
     * Check if current route matches
     */
    public function isActiveRoute($route) {
        $currentRoute = $_SERVER['REQUEST_URI'] ?? '';
        return strpos($currentRoute, $route) === 0;
    }
    
    /**
     * Flash message display
     */
    public function flash($type = null) {
        if (!isset($_SESSION['flash'])) {
            return '';
        }
        
        $flash = $_SESSION['flash'];
        unset($_SESSION['flash']);
        
        if ($type) {
            return $flash[$type] ?? '';
        }
        
        return $flash;
    }
    
    /**
     * VULNERABLE FUNCTIONS FOR LEARNING
     * These demonstrate common XSS vulnerabilities
     */
    
    /**
     * Insecure template rendering (vulnerable to XSS)
     */
    public function renderUnsafe($template, $data = []) {
        return $this->render($template, $data, false);
    }
    
    /**
     * Insecure variable interpolation
     */
    public function insecureVar($name) {
        return $this->data[$name] ?? '';
    }
    
    /**
     * Insecure include (vulnerable to local file inclusion)
     */
    public function insecureInclude($template) {
        // WARNING: This is vulnerable to LFI
        $templatePath = $this->viewPath . '/' . $template;
        if (file_exists($templatePath)) {
            extract($this->data);
            include $templatePath;
        }
    }
}

/**
 * Template Helper Functions
 * These are global functions available in all templates
 */

/**
 * Quick template rendering function
 */
function view($template, $data = [], $secure = true) {
    $templateEngine = new Template();
    return $templateEngine->render($template, $data, $secure);
}

/**
 * Secure output function (shorthand)
 */
function e($value, $encoding = 'UTF-8') {
    return htmlspecialchars($value ?? '', ENT_QUOTES | ENT_HTML5, $encoding);
}

/**
 * Raw output function (use with caution)
 */
function raw($value) {
    return $value;
}

/**
 * JSON encoding for JavaScript
 */
function json($value) {
    return json_encode($value, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP);
}

/**
 * URL generation
 */
function url($path = '') {
    return APP_URL . '/' . ltrim($path, '/');
}

/**
 * Asset URL generation
 */
function asset($path) {
    return APP_URL . '/assets/' . ltrim($path, '/');
}

/**
 * CSRF token generation
 */
function csrf_token() {
    return generateCSRFToken();
}

/**
 * CSRF field generation
 */
function csrf_field() {
    $token = generateCSRFToken();
    return "<input type=\"hidden\" name=\"csrf_token\" value=\"" . e($token) . "\">";
}

/**
 * Old input value (for form repopulation after validation errors)
 */
function old($key, $default = '') {
    return $_SESSION['old_input'][$key] ?? $default;
}

/**
 * Error message display
 */
function error($key) {
    return $_SESSION['errors'][$key] ?? '';
}

/**
 * Check if error exists
 */
function hasError($key) {
    return isset($_SESSION['errors'][$key]);
}

/**
 * LEARNING EXAMPLES AND TESTING FUNCTIONS
 */

/**
 * XSS Testing Helper
 */
function xssTest($input, $context = 'html') {
    echo "<div class='xss-test'>";
    echo "<h4>XSS Test - $context Context</h4>";
    echo "<p><strong>Input:</strong> " . e($input) . "</p>";
    echo "<p><strong>Secure Output:</strong> " . e($input) . "</p>";
    echo "<p><strong>Insecure Output:</strong> " . $input . "</p>";
    echo "</div>";
}

/**
 * Template Security Demo
 */
function templateSecurityDemo($userInput) {
    $template = new Template();
    
    echo "<div class='security-demo'>";
    echo "<h3>Template Security Demonstration</h3>";
    
    // Secure rendering
    echo "<h4>Secure Mode (XSS Protected):</h4>";
    echo "<div class='secure'>";
    $secureOutput = $template->render('demo/security', ['userInput' => $userInput], true);
    echo $secureOutput;
    echo "</div>";
    
    // Insecure rendering
    echo "<h4>Insecure Mode (XSS Vulnerable):</h4>";
    echo "<div class='insecure'>";
    $insecureOutput = $template->render('demo/security', ['userInput' => $userInput], false);
    echo $insecureOutput;
    echo "</div>";
    
    echo "</div>";
}

/**
 * LEARNING NOTES FOR BUG BOUNTY HUNTERS:
 * 
 * 1. Template Injection Vulnerabilities:
 *    - Test for server-side template injection (SSTI)
 *    - Try template syntax in user inputs: {{7*7}}, ${7*7}, etc.
 *    - Look for user-controlled template names
 * 
 * 2. XSS Prevention Testing:
 *    - Test different XSS payloads in various contexts
 *    - Check if output escaping is consistent across all templates
 *    - Test for DOM-based XSS in client-side template rendering
 * 
 * 3. Context-Aware Escaping:
 *    - HTML context: <div>USER_INPUT</div>
 *    - Attribute context: <div title="USER_INPUT">
 *    - JavaScript context: <script>var x = "USER_INPUT";</script>
 *    - CSS context: <style>.class { color: USER_INPUT; }</style>
 * 
 * 4. Template Inheritance Issues:
 *    - Test for file inclusion vulnerabilities
 *    - Check if template paths are user-controllable
 *    - Look for directory traversal in template includes
 * 
 * 5. Common XSS Bypass Techniques:
 *    - HTML entity encoding bypasses
 *    - JavaScript protocol in URLs
 *    - SVG-based XSS payloads
 *    - Event handler attributes
 *    - CSS expression() attacks (IE)
 */
?>