<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="PHP Bug Bounty Learning Environment - Learn web security through hands-on practice">
    <title><?= $this->e($title ?? 'PHP Bug Bounty Learning Environment') ?></title>
    
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    
    <!-- Font Awesome Icons -->
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    
    <!-- Custom CSS -->
    <style>
        .debug-info {
            background: #f8f9fa;
            border-left: 4px solid #007bff;
            padding: 10px;
            margin: 10px 0;
            font-size: 0.9em;
        }
        
        .vulnerability-demo {
            border: 2px solid #dc3545;
            border-radius: 5px;
            padding: 15px;
            margin: 15px 0;
            background: #fff5f5;
        }
        
        .security-demo {
            border: 2px solid #28a745;
            border-radius: 5px;
            padding: 15px;
            margin: 15px 0;
            background: #f5fff5;
        }
        
        .xss-test {
            border: 2px solid #ffc107;
            border-radius: 5px;
            padding: 15px;
            margin: 15px 0;
            background: #fffdf5;
        }
        
        .http-info {
            background: #e9ecef;
            border-radius: 5px;
            padding: 10px;
            margin: 10px 0;
        }
        
        .payload-box {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 3px;
            padding: 8px;
            font-family: monospace;
            font-size: 0.9em;
            margin: 5px 0;
        }
        
        .footer {
            margin-top: 50px;
            padding: 20px 0;
            border-top: 1px solid #dee2e6;
            background: #f8f9fa;
        }
        
        .navbar-brand {
            font-weight: bold;
        }
        
        .debug-bar {
            position: fixed;
            bottom: 0;
            left: 0;
            right: 0;
            background: #343a40;
            color: white;
            padding: 5px 10px;
            font-size: 0.8em;
            z-index: 1000;
        }
        
        .debug-toggle {
            cursor: pointer;
            float: right;
        }
        
        .debug-content {
            display: none;
            margin-top: 10px;
            max-height: 200px;
            overflow-y: auto;
        }
        
        .flash-message {
            margin-top: 10px;
        }
        
        code {
            background: #f1f1f1;
            padding: 2px 4px;
            border-radius: 3px;
        }
        
        .card-header {
            font-weight: bold;
        }
        
        .text-danger {
            color: #dc3545 !important;
        }
        
        .text-success {
            color: #28a745 !important;
        }
        
        .text-warning {
            color: #ffc107 !important;
        }
        
        .text-info {
            color: #17a2b8 !important;
        }
    </style>
    
    <!-- Security Headers (for demonstration) -->
    <?php if (!DEBUG_MODE): ?>
        <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline' cdn.jsdelivr.net cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' cdn.jsdelivr.net cdnjs.cloudflare.com;">
        <meta http-equiv="X-Content-Type-Options" content="nosniff">
        <meta http-equiv="X-Frame-Options" content="DENY">
        <meta http-equiv="X-XSS-Protection" content="1; mode=block">
    <?php endif; ?>
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="/">
                <i class="fas fa-shield-alt"></i>
                <?= APP_NAME ?>
            </a>
            
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto">
                    <li class="nav-item">
                        <a class="nav-link <?= $this->isActiveRoute('/') ? 'active' : '' ?>" href="/">
                            <i class="fas fa-home"></i> Home
                        </a>
                    </li>
                    
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" id="demoDropdown" role="button" data-bs-toggle="dropdown">
                            <i class="fas fa-bug"></i> Vulnerabilities
                        </a>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="/demo/sql-injection">
                                <i class="fas fa-database"></i> SQL Injection
                            </a></li>
                            <li><a class="dropdown-item" href="/demo/xss">
                                <i class="fas fa-code"></i> XSS (Cross-Site Scripting)
                            </a></li>
                            <li><a class="dropdown-item" href="/demo/csrf">
                                <i class="fas fa-user-shield"></i> CSRF Protection
                            </a></li>
                            <li><a class="dropdown-item" href="/demo/session">
                                <i class="fas fa-key"></i> Session Management
                            </a></li>
                        </ul>
                    </li>
                    
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" id="learningDropdown" role="button" data-bs-toggle="dropdown">
                            <i class="fas fa-graduation-cap"></i> Learning
                        </a>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="/http-info">
                                <i class="fas fa-info-circle"></i> HTTP Workflow
                            </a></li>
                            <li><a class="dropdown-item" href="/files">
                                <i class="fas fa-file-upload"></i> File Operations
                            </a></li>
                            <li><a class="dropdown-item" href="/api/users">
                                <i class="fas fa-plug"></i> API Testing
                            </a></li>
                        </ul>
                    </li>
                    
                    <?php if (session()->isAuthenticated()): ?>
                        <li class="nav-item dropdown">
                            <a class="nav-link dropdown-toggle" href="#" id="adminDropdown" role="button" data-bs-toggle="dropdown">
                                <i class="fas fa-cog"></i> Admin
                            </a>
                            <ul class="dropdown-menu">
                                <li><a class="dropdown-item" href="/admin">
                                    <i class="fas fa-tachometer-alt"></i> Dashboard
                                </a></li>
                                <li><a class="dropdown-item" href="/admin/users">
                                    <i class="fas fa-users"></i> User Management
                                </a></li>
                            </ul>
                        </li>
                    <?php endif; ?>
                </ul>
                
                <ul class="navbar-nav">
                    <?php if (session()->isAuthenticated()): ?>
                        <li class="nav-item dropdown">
                            <a class="nav-link dropdown-toggle" href="#" id="userDropdown" role="button" data-bs-toggle="dropdown">
                                <i class="fas fa-user"></i> 
                                User: <?= $this->e(session()->get('username', 'Unknown')) ?>
                            </a>
                            <ul class="dropdown-menu">
                                <li><a class="dropdown-item" href="/demo/session?action=logout">
                                    <i class="fas fa-sign-out-alt"></i> Logout
                                </a></li>
                            </ul>
                        </li>
                    <?php else: ?>
                        <li class="nav-item">
                            <a class="nav-link" href="/demo/session?action=login">
                                <i class="fas fa-sign-in-alt"></i> Demo Login
                            </a>
                        </li>
                    <?php endif; ?>
                    
                    <?php if (DEBUG_MODE): ?>
                        <li class="nav-item">
                            <span class="nav-link text-warning">
                                <i class="fas fa-exclamation-triangle"></i> DEBUG
                            </span>
                        </li>
                    <?php endif; ?>
                </ul>
            </div>
        </div>
    </nav>

    <!-- Flash Messages -->
    <?php 
    $flashMessages = session()->getAllFlash();
    if (!empty($flashMessages)): 
    ?>
        <div class="container mt-3">
            <?php foreach ($flashMessages as $type => $message): ?>
                <div class="alert alert-<?= $type === 'error' ? 'danger' : $type ?> alert-dismissible fade show flash-message" role="alert">
                    <?php
                    $icon = match($type) {
                        'success' => 'fas fa-check-circle',
                        'error' => 'fas fa-exclamation-circle',
                        'warning' => 'fas fa-exclamation-triangle',
                        'info' => 'fas fa-info-circle',
                        default => 'fas fa-bell'
                    };
                    ?>
                    <i class="<?= $icon ?>"></i>
                    <?= $this->e($message) ?>
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                </div>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>

    <!-- Main Content -->
    <main class="container mt-4">
        <?= $this->yieldSection('content') ?>
    </main>

    <!-- Footer -->
    <footer class="footer">
        <div class="container">
            <div class="row">
                <div class="col-md-6">
                    <h5>PHP Bug Bounty Learning Environment</h5>
                    <p class="text-muted">
                        Version <?= APP_VERSION ?> • 
                        Educational use only • 
                        <a href="https://github.com/owasp/top-ten" target="_blank">OWASP Top 10</a>
                    </p>
                </div>
                <div class="col-md-6 text-end">
                    <h6>Learning Resources</h6>
                    <ul class="list-unstyled">
                        <li><a href="https://portswigger.net/web-security" target="_blank" class="text-decoration-none">
                            <i class="fas fa-external-link-alt"></i> PortSwigger Academy
                        </a></li>
                        <li><a href="https://owasp.org/www-project-top-ten/" target="_blank" class="text-decoration-none">
                            <i class="fas fa-external-link-alt"></i> OWASP Top 10
                        </a></li>
                        <li><a href="https://github.com/jhaddix/tbhm" target="_blank" class="text-decoration-none">
                            <i class="fas fa-external-link-alt"></i> Bug Bounty Methodology
                        </a></li>
                    </ul>
                </div>
            </div>
            
            <hr>
            
            <div class="row">
                <div class="col-12 text-center">
                    <p class="text-muted mb-0">
                        <strong>⚠️ WARNING:</strong> This application contains intentional security vulnerabilities for educational purposes. 
                        <strong>Never deploy to production or public servers!</strong>
                    </p>
                </div>
            </div>
        </div>
    </footer>

    <!-- Debug Information Bar (only in debug mode) -->
    <?php if (DEBUG_MODE && isset($http_info)): ?>
        <div class="debug-bar">
            <div class="debug-toggle" onclick="toggleDebugContent()">
                <i class="fas fa-bug"></i> Debug Info <i class="fas fa-chevron-up" id="debug-icon"></i>
            </div>
            
            <strong>Request:</strong> <?= $this->e($http_info['method'] ?? 'GET') ?> <?= $this->e($http_info['uri'] ?? '/') ?> •
            <strong>Session:</strong> <?= session()->getId() ?> •
            <strong>User:</strong> <?= session()->isAuthenticated() ? session()->get('username', 'Auth') : 'Guest' ?> •
            <strong>Time:</strong> <?= date('H:i:s') ?>
            
            <div class="debug-content" id="debug-content">
                <div class="row">
                    <div class="col-md-3">
                        <strong>HTTP Info:</strong><br>
                        Method: <?= $this->e($http_info['method'] ?? 'GET') ?><br>
                        Protocol: <?= $this->e($http_info['protocol'] ?? 'HTTP/1.1') ?><br>
                        Remote IP: <?= $this->e($http_info['remote_addr'] ?? 'unknown') ?>
                    </div>
                    <div class="col-md-3">
                        <strong>Session Info:</strong><br>
                        Authenticated: <?= session()->isAuthenticated() ? 'Yes' : 'No' ?><br>
                        Session ID: <?= substr(session()->getId(), 0, 8) ?>...<br>
                        User ID: <?= session()->getUserId() ?? 'None' ?>
                    </div>
                    <div class="col-md-3">
                        <strong>Database:</strong><br>
                        Connected: Yes<br>
                        Users: <?= isset($stats['users_count']) ? $stats['users_count'] : 'N/A' ?><br>
                        Posts: <?= isset($stats['posts_count']) ? $stats['posts_count'] : 'N/A' ?>
                    </div>
                    <div class="col-md-3">
                        <strong>Security:</strong><br>
                        CSRF Token: <?= substr(csrf_token(), 0, 8) ?>...<br>
                        Debug Mode: On<br>
                        PHP Version: <?= PHP_VERSION ?>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Add padding to body when debug bar is visible -->
        <style>
            body { padding-bottom: 60px; }
        </style>
    <?php endif; ?>

    <!-- Bootstrap JavaScript -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    
    <!-- Custom JavaScript -->
    <script>
        // Debug bar toggle functionality
        function toggleDebugContent() {
            const content = document.getElementById('debug-content');
            const icon = document.getElementById('debug-icon');
            
            if (content.style.display === 'none' || content.style.display === '') {
                content.style.display = 'block';
                icon.className = 'fas fa-chevron-down';
            } else {
                content.style.display = 'none';
                icon.className = 'fas fa-chevron-up';
            }
        }
        
        // HTTP Methods demonstration
        function testHttpMethod(method, url, data = null) {
            const options = {
                method: method,
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                }
            };
            
            if (data && (method === 'POST' || method === 'PUT' || method === 'PATCH')) {
                options.body = JSON.stringify(data);
            }
            
            fetch(url, options)
                .then(response => response.json())
                .then(data => {
                    console.log(`${method} Response:`, data);
                    alert(`${method} request successful! Check console for details.`);
                })
                .catch(error => {
                    console.error(`${method} Error:`, error);
                    alert(`${method} request failed! Check console for details.`);
                });
        }
        
        // Copy text to clipboard
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                // Create temporary feedback
                const feedback = document.createElement('span');
                feedback.textContent = ' ✓ Copied!';
                feedback.style.color = '#28a745';
                feedback.style.fontSize = '0.8em';
                
                // Add to page temporarily
                document.body.appendChild(feedback);
                setTimeout(() => {
                    document.body.removeChild(feedback);
                }, 2000);
            });
        }
        
        // XSS demonstration helpers
        function demonstrateXSS(payload, context) {
            console.log(`XSS Test - Context: ${context}, Payload: ${payload}`);
            
            // In a real application, this would be dangerous
            // Here we're just logging for educational purposes
            alert(`XSS payload tested in ${context} context. Check console for details.`);
        }
        
        // SQL Injection testing helper
        function testSQLPayload(payload) {
            console.log(`SQL Injection Test - Payload: ${payload}`);
            
            // Construct URL for testing
            const testUrl = `/demo/sql-injection?search=${encodeURIComponent(payload)}&mode=vulnerable`;
            console.log(`Test URL: ${testUrl}`);
            
            alert(`SQL injection payload ready for testing. Check console for URL.`);
        }
        
        // CSRF demonstration
        function submitCSRFForm(withToken = true) {
            const form = document.getElementById('csrf-test-form');
            if (!form) return;
            
            if (!withToken) {
                // Remove CSRF token for demonstration
                const tokenField = form.querySelector('input[name="csrf_token"]');
                if (tokenField) {
                    tokenField.remove();
                }
            }
            
            form.submit();
        }
        
        // Session management helpers
        function regenerateSession() {
            fetch('/demo/session?action=regenerate', { method: 'GET' })
                .then(response => {
                    if (response.ok) {
                        location.reload();
                    }
                });
        }
        
        // File upload validation
        function validateFileUpload(input) {
            const file = input.files[0];
            if (!file) return true;
            
            const maxSize = 5 * 1024 * 1024; // 5MB
            const allowedTypes = ['jpg', 'jpeg', 'png', 'gif', 'pdf', 'txt'];
            const extension = file.name.split('.').pop().toLowerCase();
            
            if (file.size > maxSize) {
                alert('File size exceeds 5MB limit');
                return false;
            }
            
            if (!allowedTypes.includes(extension)) {
                alert('File type not allowed. Allowed types: ' + allowedTypes.join(', '));
                return false;
            }
            
            return true;
        }
        
        // Auto-hide flash messages after 5 seconds
        document.addEventListener('DOMContentLoaded', function() {
            const flashMessages = document.querySelectorAll('.flash-message');
            flashMessages.forEach(message => {
                setTimeout(() => {
                    const alert = bootstrap.Alert.getOrCreateInstance(message);
                    alert.close();
                }, 5000);
            });
        });
        
        // Security warning for production
        <?php if (!DEBUG_MODE): ?>
        console.warn('⚠️ Security Notice: This application is for educational purposes only!');
        <?php endif; ?>
        
        // Log HTTP request details for learning
        console.group('🔍 HTTP Request Analysis');
        console.log('Method:', '<?= $_SERVER['REQUEST_METHOD'] ?? 'GET' ?>');
        console.log('URL:', '<?= $_SERVER['REQUEST_URI'] ?? '/' ?>');
        console.log('User Agent:', '<?= substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 50) ?>...');
        console.log('Session ID:', '<?= substr(session_id(), 0, 16) ?>...');
        console.groupEnd();
    </script>
    
    <!-- Additional page-specific scripts -->
    <?= $this->yieldSection('scripts') ?>
</body>
</html>