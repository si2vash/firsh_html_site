<?php $this->section('content'); ?>

<!-- Welcome Header -->
<div class="row mb-4">
    <div class="col-12">
        <div class="jumbotron bg-primary text-white p-5 rounded">
            <div class="container">
                <h1 class="display-4">
                    <i class="fas fa-shield-alt"></i>
                    Welcome to PHP Bug Bounty Learning Environment
                </h1>
                <p class="lead">
                    Master web application security through hands-on learning. 
                    Understand HTTP workflow, explore vulnerabilities, and practice safe exploitation techniques.
                </p>
                <hr class="my-4">
                <p>
                    This environment demonstrates real-world vulnerabilities in a controlled setting. 
                    Perfect for aspiring bug bounty hunters, security researchers, and developers.
                </p>
                <?php if (!session()->isAuthenticated()): ?>
                    <a class="btn btn-light btn-lg" href="/demo/session?action=login" role="button">
                        <i class="fas fa-rocket"></i> Start Learning
                    </a>
                <?php endif; ?>
            </div>
        </div>
    </div>
</div>

<!-- HTTP Workflow Demonstration -->
<div class="row mb-4">
    <div class="col-12">
        <div class="card">
            <div class="card-header bg-info text-white">
                <h5 class="mb-0">
                    <i class="fas fa-exchange-alt"></i>
                    HTTP Request/Response Workflow
                </h5>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-6">
                        <h6>Current Request Information:</h6>
                        <div class="http-info">
                            <strong>Method:</strong> <?= $this->e($http_info['method']) ?><br>
                            <strong>URI:</strong> <?= $this->e($http_info['uri']) ?><br>
                            <strong>Protocol:</strong> <?= $this->e($http_info['protocol']) ?><br>
                            <strong>User Agent:</strong> <?= $this->e(substr($http_info['user_agent'], 0, 50)) ?>...<br>
                            <strong>Remote IP:</strong> <?= $this->e($http_info['remote_addr']) ?><br>
                            <strong>Timestamp:</strong> <?= $this->e($http_info['timestamp']) ?>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <h6>HTTP Workflow Steps:</h6>
                        <ol class="list-group list-group-numbered">
                            <li class="list-group-item d-flex justify-content-between align-items-start">
                                <div class="ms-2 me-auto">
                                    <div class="fw-bold">Browser Request</div>
                                    Client sends HTTP request to server
                                </div>
                                <span class="badge bg-primary rounded-pill">1</span>
                            </li>
                            <li class="list-group-item d-flex justify-content-between align-items-start">
                                <div class="ms-2 me-auto">
                                    <div class="fw-bold">Routing</div>
                                    Server routes request to controller
                                </div>
                                <span class="badge bg-primary rounded-pill">2</span>
                            </li>
                            <li class="list-group-item d-flex justify-content-between align-items-start">
                                <div class="ms-2 me-auto">
                                    <div class="fw-bold">Processing</div>
                                    Controller processes business logic
                                </div>
                                <span class="badge bg-primary rounded-pill">3</span>
                            </li>
                            <li class="list-group-item d-flex justify-content-between align-items-start">
                                <div class="ms-2 me-auto">
                                    <div class="fw-bold">Response</div>
                                    Server sends HTTP response back
                                </div>
                                <span class="badge bg-primary rounded-pill">4</span>
                            </li>
                        </ol>
                    </div>
                </div>
                <div class="mt-3">
                    <a href="/http-info" class="btn btn-outline-info">
                        <i class="fas fa-info-circle"></i> View Detailed HTTP Information
                    </a>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Quick Statistics -->
<div class="row mb-4">
    <div class="col-md-3">
        <div class="card text-center">
            <div class="card-body">
                <i class="fas fa-users fa-2x text-primary mb-2"></i>
                <h4><?= isset($stats['users_count']) ? $stats['users_count'] : 'N/A' ?></h4>
                <p class="text-muted">Total Users</p>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card text-center">
            <div class="card-body">
                <i class="fas fa-newspaper fa-2x text-success mb-2"></i>
                <h4><?= isset($stats['published_posts']) ? $stats['published_posts'] : 'N/A' ?></h4>
                <p class="text-muted">Published Posts</p>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card text-center">
            <div class="card-body">
                <i class="fas fa-user-check fa-2x text-info mb-2"></i>
                <h4><?= isset($stats['active_users']) ? $stats['active_users'] : 'N/A' ?></h4>
                <p class="text-muted">Active Users</p>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card text-center">
            <div class="card-body">
                <i class="fas fa-key fa-2x text-warning mb-2"></i>
                <h4><?= session()->getId() ? 'Active' : 'None' ?></h4>
                <p class="text-muted">Session Status</p>
            </div>
        </div>
    </div>
</div>

<!-- Recent Posts -->
<?php if (!empty($recent_posts)): ?>
<div class="row mb-4">
    <div class="col-12">
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0">
                    <i class="fas fa-newspaper"></i>
                    Recent Posts
                </h5>
            </div>
            <div class="card-body">
                <div class="row">
                    <?php foreach (array_slice($recent_posts, 0, 3) as $post): ?>
                        <div class="col-md-4 mb-3">
                            <div class="card h-100">
                                <div class="card-body">
                                    <h6 class="card-title"><?= $this->e($post['title']) ?></h6>
                                    <p class="card-text text-muted">
                                        <?= $this->truncate($this->e($post['content']), 80) ?>
                                    </p>
                                    <small class="text-muted">
                                        By: <?= $this->e($post['username']) ?> •
                                        <?= $this->formatDate($post['created_at'], 'M j, Y') ?>
                                    </small>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>
        </div>
    </div>
</div>
<?php endif; ?>

<!-- Session & Authentication Demo -->
<div class="row mb-4">
    <div class="col-12">
        <div class="card">
            <div class="card-header bg-warning text-dark">
                <h5 class="mb-0">
                    <i class="fas fa-key"></i>
                    Session & Authentication Demonstration
                </h5>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-6">
                        <h6>Current Session State:</h6>
                        <ul class="list-group list-group-flush">
                            <li class="list-group-item d-flex justify-content-between">
                                <span>Authenticated:</span>
                                <span class="badge bg-<?= session()->isAuthenticated() ? 'success' : 'secondary' ?>">
                                    <?= session()->isAuthenticated() ? 'Yes' : 'No' ?>
                                </span>
                            </li>
                            <li class="list-group-item d-flex justify-content-between">
                                <span>Session ID:</span>
                                <code><?= substr(session()->getId(), 0, 16) ?>...</code>
                            </li>
                            <li class="list-group-item d-flex justify-content-between">
                                <span>User ID:</span>
                                <span><?= session()->getUserId() ?? 'None' ?></span>
                            </li>
                            <li class="list-group-item d-flex justify-content-between">
                                <span>Username:</span>
                                <span><?= session()->get('username', 'Guest') ?></span>
                            </li>
                        </ul>
                    </div>
                    <div class="col-md-6">
                        <h6>Session Actions:</h6>
                        <div class="d-grid gap-2">
                            <?php if (!session()->isAuthenticated()): ?>
                                <a href="/demo/session?action=login" class="btn btn-success">
                                    <i class="fas fa-sign-in-alt"></i> Demo Login
                                </a>
                            <?php else: ?>
                                <a href="/demo/session?action=logout" class="btn btn-danger">
                                    <i class="fas fa-sign-out-alt"></i> Logout
                                </a>
                                <a href="/demo/session?action=regenerate" class="btn btn-info">
                                    <i class="fas fa-sync"></i> Regenerate Session ID
                                </a>
                            <?php endif; ?>
                            <?php if (DEBUG_MODE): ?>
                                <a href="/demo/session?action=test_fixation" class="btn btn-warning">
                                    <i class="fas fa-exclamation-triangle"></i> Test Session Fixation
                                </a>
                            <?php endif; ?>
                            <a href="/demo/session" class="btn btn-outline-primary">
                                <i class="fas fa-cog"></i> Session Management Demo
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Vulnerability Testing Links -->
<div class="row mb-4">
    <div class="col-12">
        <div class="card border-danger">
            <div class="card-header bg-danger text-white">
                <h5 class="mb-0">
                    <i class="fas fa-bug"></i>
                    Vulnerability Testing Laboratory
                </h5>
            </div>
            <div class="card-body">
                <p class="text-muted">
                    <strong>⚠️ Educational Purpose Only:</strong> 
                    These demonstrations contain intentional vulnerabilities for learning. 
                    Practice safe exploitation techniques in this controlled environment.
                </p>
                
                <div class="row">
                    <div class="col-md-6 mb-3">
                        <div class="card h-100 border-danger">
                            <div class="card-header bg-light">
                                <h6 class="text-danger mb-0">
                                    <i class="fas fa-database"></i> SQL Injection
                                </h6>
                            </div>
                            <div class="card-body">
                                <p class="card-text">
                                    Learn about SQL injection attacks through prepared statements vs raw queries.
                                    Test various injection techniques safely.
                                </p>
                                <a href="/demo/sql-injection" class="btn btn-outline-danger">
                                    <i class="fas fa-flask"></i> Test SQL Injection
                                </a>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-6 mb-3">
                        <div class="card h-100 border-warning">
                            <div class="card-header bg-light">
                                <h6 class="text-warning mb-0">
                                    <i class="fas fa-code"></i> Cross-Site Scripting (XSS)
                                </h6>
                            </div>
                            <div class="card-body">
                                <p class="card-text">
                                    Understand XSS vulnerabilities and context-aware output escaping.
                                    Practice payload construction and mitigation.
                                </p>
                                <a href="/demo/xss" class="btn btn-outline-warning">
                                    <i class="fas fa-flask"></i> Test XSS Vulnerabilities
                                </a>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-6 mb-3">
                        <div class="card h-100 border-info">
                            <div class="card-header bg-light">
                                <h6 class="text-info mb-0">
                                    <i class="fas fa-user-shield"></i> CSRF Protection
                                </h6>
                            </div>
                            <div class="card-body">
                                <p class="card-text">
                                    Learn about Cross-Site Request Forgery attacks and token-based protection mechanisms.
                                </p>
                                <a href="/demo/csrf" class="btn btn-outline-info">
                                    <i class="fas fa-flask"></i> Test CSRF Protection
                                </a>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-6 mb-3">
                        <div class="card h-100 border-success">
                            <div class="card-header bg-light">
                                <h6 class="text-success mb-0">
                                    <i class="fas fa-file-upload"></i> File Operations
                                </h6>
                            </div>
                            <div class="card-body">
                                <p class="card-text">
                                    Explore file upload security, validation bypasses, and path traversal vulnerabilities.
                                </p>
                                <a href="/files" class="btn btn-outline-success">
                                    <i class="fas fa-flask"></i> Test File Operations
                                </a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Learning Resources -->
<div class="row mb-4">
    <div class="col-12">
        <div class="card">
            <div class="card-header bg-success text-white">
                <h5 class="mb-0">
                    <i class="fas fa-graduation-cap"></i>
                    Learning Resources & Next Steps
                </h5>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-4">
                        <h6>Core Concepts:</h6>
                        <ul class="list-unstyled">
                            <li>
                                <a href="/http-info" class="text-decoration-none">
                                    <i class="fas fa-info-circle text-primary"></i> HTTP Workflow Analysis
                                </a>
                            </li>
                            <li>
                                <a href="/demo/session" class="text-decoration-none">
                                    <i class="fas fa-key text-warning"></i> Session Management
                                </a>
                            </li>
                            <li>
                                <a href="/api/users" class="text-decoration-none">
                                    <i class="fas fa-plug text-info"></i> API Security Testing
                                </a>
                            </li>
                        </ul>
                    </div>
                    <div class="col-md-4">
                        <h6>Quick Bug Bounty Tips:</h6>
                        <ul class="list-unstyled">
                            <li><i class="fas fa-check text-success"></i> Always test input validation</li>
                            <li><i class="fas fa-check text-success"></i> Check authentication bypasses</li>
                            <li><i class="fas fa-check text-success"></i> Look for information disclosure</li>
                            <li><i class="fas fa-check text-success"></i> Test different HTTP methods</li>
                            <li><i class="fas fa-check text-success"></i> Analyze error messages</li>
                        </ul>
                    </div>
                    <div class="col-md-4">
                        <h6>External Resources:</h6>
                        <ul class="list-unstyled">
                            <li>
                                <a href="https://portswigger.net/web-security" target="_blank" class="text-decoration-none">
                                    <i class="fas fa-external-link-alt"></i> PortSwigger Academy
                                </a>
                            </li>
                            <li>
                                <a href="https://owasp.org/www-project-top-ten/" target="_blank" class="text-decoration-none">
                                    <i class="fas fa-external-link-alt"></i> OWASP Top 10
                                </a>
                            </li>
                            <li>
                                <a href="https://github.com/jhaddix/tbhm" target="_blank" class="text-decoration-none">
                                    <i class="fas fa-external-link-alt"></i> Bug Bounty Methodology
                                </a>
                            </li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Debug Information (if debug mode is enabled) -->
<?php if (DEBUG_MODE): ?>
<div class="row mb-4">
    <div class="col-12">
        <div class="card border-info">
            <div class="card-header bg-info text-white">
                <h5 class="mb-0">
                    <i class="fas fa-bug"></i>
                    Debug Information
                </h5>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-4">
                        <h6>Environment:</h6>
                        <ul class="list-unstyled">
                            <li><strong>PHP Version:</strong> <?= PHP_VERSION ?></li>
                            <li><strong>Debug Mode:</strong> <span class="badge bg-warning">Enabled</span></li>
                            <li><strong>App Version:</strong> <?= APP_VERSION ?></li>
                        </ul>
                    </div>
                    <div class="col-md-4">
                        <h6>Security Status:</h6>
                        <ul class="list-unstyled">
                            <li><strong>CSRF Token:</strong> <code><?= substr(csrf_token(), 0, 16) ?>...</code></li>
                            <li><strong>Session Security:</strong> <span class="badge bg-success">Active</span></li>
                            <li><strong>Input Sanitization:</strong> <span class="badge bg-success">Enabled</span></li>
                        </ul>
                    </div>
                    <div class="col-md-4">
                        <h6>Testing Tips:</h6>
                        <ul class="list-unstyled text-muted">
                            <li><i class="fas fa-lightbulb"></i> Use browser DevTools Network tab</li>
                            <li><i class="fas fa-lightbulb"></i> Check console for JavaScript errors</li>
                            <li><i class="fas fa-lightbulb"></i> Monitor HTTP status codes</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
<?php endif; ?>

<?php $this->endSection(); ?>

<?php $this->section('scripts'); ?>
<script>
// Demo functions for the home page
function quickSQLTest() {
    const payload = "' OR '1'='1";
    const url = `/demo/sql-injection?search=${encodeURIComponent(payload)}&mode=vulnerable`;
    window.open(url, '_blank');
}

function quickXSSTest() {
    const payload = "<script>alert('XSS Test')</script>";
    const url = `/demo/xss?input=${encodeURIComponent(payload)}&context=html`;
    window.open(url, '_blank');
}

function testAPIEndpoint() {
    fetch('/api/users')
        .then(response => {
            if (response.status === 401) {
                alert('Authentication required! Please login first.');
                return { error: 'Authentication required' };
            }
            return response.json();
        })
        .then(data => {
            console.log('API Response:', data);
            if (data.error) {
                alert('API Error: ' + data.error);
            } else {
                alert('API request successful! Check console for details.');
            }
        })
        .catch(error => {
            console.error('API Error:', error);
            alert('API request failed! Check console for details.');
        });
}

// Auto-refresh stats every 30 seconds (for demonstration)
setInterval(() => {
    if (DEBUG_MODE) {
        console.log('Stats refresh (demo)');
    }
}, 30000);

// Log page load for learning
console.group('🏠 Home Page Analytics');
console.log('Page loaded at:', new Date().toISOString());
console.log('Session authenticated:', <?= session()->isAuthenticated() ? 'true' : 'false' ?>);
console.log('Debug mode:', <?= DEBUG_MODE ? 'true' : 'false' ?>);
console.log('User agent:', navigator.userAgent.substr(0, 50) + '...');
console.groupEnd();
</script>
<?php $this->endSection(); ?>