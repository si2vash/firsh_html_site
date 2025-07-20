<?php
/**
 * Setup Script for PHP Bug Bounty Learning Environment
 * 
 * This script:
 * 1. Checks system requirements
 * 2. Creates database and tables
 * 3. Inserts sample data
 * 4. Configures directories and permissions
 * 5. Validates installation
 */

// Prevent running this in a web browser for security
if (isset($_SERVER['HTTP_HOST'])) {
    die("This script must be run from the command line for security reasons.\n");
}

// Start output
echo "\n";
echo "=======================================================\n";
echo "  PHP Bug Bounty Learning Environment Setup\n";
echo "=======================================================\n\n";

// Step 1: Check PHP version
echo "Step 1: Checking PHP requirements...\n";
$phpVersion = phpversion();
echo "- PHP Version: $phpVersion\n";

if (version_compare($phpVersion, '8.0.0', '<')) {
    echo "❌ Error: PHP 8.0.0 or higher is required.\n";
    exit(1);
}
echo "✅ PHP version is compatible\n\n";

// Step 2: Check required extensions
echo "Step 2: Checking required PHP extensions...\n";
$requiredExtensions = ['pdo', 'mbstring', 'json', 'session'];
// Add database-specific extension
if (defined('DB_TYPE') && DB_TYPE === 'sqlite') {
    $requiredExtensions[] = 'pdo_sqlite';
} else {
    $requiredExtensions[] = 'pdo_mysql';
}
$missingExtensions = [];

foreach ($requiredExtensions as $extension) {
    if (extension_loaded($extension)) {
        echo "✅ $extension extension is loaded\n";
    } else {
        echo "❌ $extension extension is missing\n";
        $missingExtensions[] = $extension;
    }
}

if (!empty($missingExtensions)) {
    echo "\nError: Missing required PHP extensions: " . implode(', ', $missingExtensions) . "\n";
    echo "Please install the missing extensions and try again.\n";
    exit(1);
}
echo "\n";

// Step 3: Load configuration
echo "Step 3: Loading configuration...\n";
require_once 'config/app.php';
echo "✅ Configuration loaded successfully\n\n";

// Step 4: Check database connection
echo "Step 4: Checking database connection...\n";
try {
    $dsn = "mysql:host=" . DB_HOST . ";charset=" . DB_CHARSET;
    $pdo = new PDO($dsn, DB_USER, DB_PASS, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
    ]);
    echo "✅ Database connection successful\n";
} catch (PDOException $e) {
    echo "❌ Database connection failed: " . $e->getMessage() . "\n";
    echo "Please check your database configuration in config/app.php\n";
    exit(1);
}

// Step 5: Create database if it doesn't exist
echo "\nStep 5: Creating database...\n";
try {
    $pdo->exec("CREATE DATABASE IF NOT EXISTS `" . DB_NAME . "` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
    echo "✅ Database '" . DB_NAME . "' created or already exists\n";
    
    // Connect to the specific database
    $dsn = "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=" . DB_CHARSET;
    $pdo = new PDO($dsn, DB_USER, DB_PASS, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
    ]);
    echo "✅ Connected to database '" . DB_NAME . "'\n";
} catch (PDOException $e) {
    echo "❌ Failed to create database: " . $e->getMessage() . "\n";
    exit(1);
}

// Step 6: Create tables
echo "\nStep 6: Creating database tables...\n";

// Users table
try {
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            email VARCHAR(100) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            role ENUM('user', 'admin') DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT TRUE,
            INDEX idx_username (username),
            INDEX idx_email (email),
            INDEX idx_role (role)
        ) ENGINE=InnoDB
    ");
    echo "✅ Users table created\n";
} catch (PDOException $e) {
    echo "❌ Failed to create users table: " . $e->getMessage() . "\n";
    exit(1);
}

// Posts table
try {
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS posts (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            title VARCHAR(200) NOT NULL,
            content TEXT,
            status ENUM('draft', 'published') DEFAULT 'draft',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            INDEX idx_user_id (user_id),
            INDEX idx_status (status),
            INDEX idx_created_at (created_at)
        ) ENGINE=InnoDB
    ");
    echo "✅ Posts table created\n";
} catch (PDOException $e) {
    echo "❌ Failed to create posts table: " . $e->getMessage() . "\n";
    exit(1);
}

// Security logs table
try {
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS security_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            event_type VARCHAR(50) NOT NULL,
            user_id INT NULL,
            ip_address VARCHAR(45),
            user_agent TEXT,
            details JSON,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_event_type (event_type),
            INDEX idx_created_at (created_at),
            INDEX idx_ip_address (ip_address)
        ) ENGINE=InnoDB
    ");
    echo "✅ Security logs table created\n";
} catch (PDOException $e) {
    echo "❌ Failed to create security_logs table: " . $e->getMessage() . "\n";
    exit(1);
}

// Step 7: Insert sample data
echo "\nStep 7: Inserting sample data...\n";

// Check if data already exists
$stmt = $pdo->query("SELECT COUNT(*) FROM users");
$userCount = $stmt->fetchColumn();

if ($userCount == 0) {
    // Insert admin user
    try {
        $stmt = $pdo->prepare("
            INSERT INTO users (username, email, password, role) 
            VALUES (?, ?, ?, ?)
        ");
        $stmt->execute([
            'admin',
            'admin@example.com',
            password_hash('admin123', PASSWORD_DEFAULT),
            'admin'
        ]);
        echo "✅ Admin user created (username: admin, password: admin123)\n";
    } catch (PDOException $e) {
        echo "❌ Failed to create admin user: " . $e->getMessage() . "\n";
    }
    
    // Insert test user
    try {
        $stmt = $pdo->prepare("
            INSERT INTO users (username, email, password, role) 
            VALUES (?, ?, ?, ?)
        ");
        $stmt->execute([
            'testuser',
            'test@example.com',
            password_hash('password', PASSWORD_DEFAULT),
            'user'
        ]);
        echo "✅ Test user created (username: testuser, password: password)\n";
    } catch (PDOException $e) {
        echo "❌ Failed to create test user: " . $e->getMessage() . "\n";
    }
    
    // Insert sample posts
    try {
        $stmt = $pdo->prepare("
            INSERT INTO posts (user_id, title, content, status) 
            VALUES (?, ?, ?, ?)
        ");
        
        $posts = [
            [1, 'Welcome to Bug Bounty Learning', 'This is a comprehensive learning environment for web application security testing. Here you can practice finding vulnerabilities in a safe, controlled environment.', 'published'],
            [1, 'Understanding SQL Injection', 'SQL injection is one of the most common web application vulnerabilities. It occurs when user input is not properly sanitized before being used in SQL queries.', 'published'],
            [2, 'XSS Prevention Techniques', 'Cross-Site Scripting (XSS) attacks can be prevented through proper input validation and output encoding. Always escape user input before displaying it.', 'published'],
            [2, 'Session Management Best Practices', 'Secure session management is crucial for web application security. Use HTTPOnly cookies, secure flags, and implement proper session timeouts.', 'draft']
        ];
        
        foreach ($posts as $post) {
            $stmt->execute($post);
        }
        echo "✅ Sample posts created\n";
    } catch (PDOException $e) {
        echo "❌ Failed to create sample posts: " . $e->getMessage() . "\n";
    }
} else {
    echo "ℹ️  Sample data already exists (found $userCount users)\n";
}

// Step 8: Create and configure directories
echo "\nStep 8: Creating directories...\n";

$directories = [
    'uploads' => 0755,
    'logs' => 0755,
];

foreach ($directories as $dir => $permissions) {
    if (!is_dir($dir)) {
        if (mkdir($dir, $permissions, true)) {
            echo "✅ Created directory: $dir\n";
        } else {
            echo "❌ Failed to create directory: $dir\n";
            exit(1);
        }
    } else {
        echo "ℹ️  Directory already exists: $dir\n";
    }
    
    // Check if directory is writable
    if (is_writable($dir)) {
        echo "✅ Directory is writable: $dir\n";
    } else {
        echo "⚠️  Warning: Directory is not writable: $dir\n";
        echo "   You may need to run: chmod $permissions $dir\n";
    }
}

// Step 9: Create .htaccess for security (Apache)
echo "\nStep 9: Creating security configuration...\n";

$htaccessContent = "# Security headers for Apache
<IfModule mod_headers.c>
    Header always set X-Content-Type-Options nosniff
    Header always set X-Frame-Options DENY
    Header always set X-XSS-Protection \"1; mode=block\"
    Header always set Referrer-Policy \"strict-origin-when-cross-origin\"
</IfModule>

# Prevent access to sensitive files
<FilesMatch \"\\.(ini|log|conf|sql)$\">
    Require all denied
</FilesMatch>

# Prevent access to directories
Options -Indexes

# PHP security
<IfModule mod_php.c>
    php_value expose_php Off
    php_value display_errors Off
    php_value log_errors On
</IfModule>
";

if (file_put_contents('.htaccess', $htaccessContent)) {
    echo "✅ Created .htaccess security configuration\n";
} else {
    echo "⚠️  Warning: Could not create .htaccess file\n";
}

// Create uploads .htaccess
$uploadsHtaccess = "# Prevent PHP execution in uploads directory
<FilesMatch \"\\.(php|phtml|php3|php4|php5|pl|py|jsp|asp|sh|cgi)$\">
    Require all denied
</FilesMatch>

# Only allow specific file types
<FilesMatch \"\\.(jpg|jpeg|png|gif|pdf|txt)$\">
    Require all granted
</FilesMatch>
";

if (file_put_contents('uploads/.htaccess', $uploadsHtaccess)) {
    echo "✅ Created uploads directory security configuration\n";
} else {
    echo "⚠️  Warning: Could not create uploads/.htaccess file\n";
}

// Step 10: Validate installation
echo "\nStep 10: Validating installation...\n";

// Test database connection with the Database class
try {
    require_once 'core/Database.php';
    $testDb = new Database();
    echo "✅ Database class works correctly\n";
} catch (Exception $e) {
    echo "❌ Database class test failed: " . $e->getMessage() . "\n";
    exit(1);
}

// Test session functionality
try {
    require_once 'core/Session.php';
    $testSession = new Session();
    echo "✅ Session class works correctly\n";
} catch (Exception $e) {
    echo "❌ Session class test failed: " . $e->getMessage() . "\n";
    exit(1);
}

// Test template engine
try {
    require_once 'core/Template.php';
    $testTemplate = new Template();
    echo "✅ Template class works correctly\n";
} catch (Exception $e) {
    echo "❌ Template class test failed: " . $e->getMessage() . "\n";
    exit(1);
}

// Test router
try {
    require_once 'core/Router.php';
    $testRouter = new Router();
    echo "✅ Router class works correctly\n";
} catch (Exception $e) {
    echo "❌ Router class test failed: " . $e->getMessage() . "\n";
    exit(1);
}

// Final success message
echo "\n=======================================================\n";
echo "  ✅ Setup completed successfully!\n";
echo "=======================================================\n\n";

echo "Next steps:\n";
echo "1. Start the PHP development server:\n";
echo "   php -S localhost:8080 -t .\n\n";
echo "2. Open your browser and visit:\n";
echo "   http://localhost:8080\n\n";
echo "3. Login credentials:\n";
echo "   Admin: admin / admin123\n";
echo "   User:  testuser / password\n\n";

echo "Security Notes:\n";
echo "⚠️  This application contains intentional vulnerabilities for learning\n";
echo "⚠️  Never deploy this to a production or public server\n";
echo "⚠️  Only use in a secure, isolated environment\n\n";

echo "Learning Resources:\n";
echo "📚 Visit /demo/sql-injection for SQL injection testing\n";
echo "📚 Visit /demo/xss for XSS vulnerability testing\n";
echo "📚 Visit /demo/csrf for CSRF protection testing\n";
echo "📚 Visit /demo/session for session management testing\n";
echo "📚 Visit /http-info for HTTP workflow analysis\n\n";

echo "Troubleshooting:\n";
echo "- If you get permission errors, check directory permissions\n";
echo "- If database connection fails, verify MySQL is running\n";
echo "- For detailed logs, check the 'logs' directory\n";
echo "- Enable DEBUG_MODE in config/app.php for detailed error messages\n\n";

echo "Happy learning! 🎯\n\n";
?>