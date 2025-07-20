<?php
/**
 * Database Class - Secure and Insecure Database Operations
 * 
 * This class demonstrates:
 * 1. PDO database connection with security configurations
 * 2. Prepared statements vs raw queries
 * 3. SQL injection vulnerabilities and prevention
 * 4. Transaction handling
 * 5. Error handling and logging
 * 6. Query optimization and debugging
 */

class Database {
    private $pdo;
    private $host;
    private $dbname;
    private $username;
    private $password;
    private $options;
    private $secureMode;
    
    public function __construct($secureMode = true) {
        $this->host = DB_HOST;
        $this->dbname = DB_NAME;
        $this->username = DB_USER;
        $this->password = DB_PASS;
        $this->secureMode = $secureMode;
        
        $this->setOptions();
        $this->connect();
        $this->initializeDatabase();
    }
    
    /**
     * Set PDO options for security and performance
     */
    private function setOptions() {
        if ($this->secureMode) {
            // Secure PDO options
            $this->options = [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false, // Use real prepared statements
                PDO::ATTR_STRINGIFY_FETCHES => false, // Keep data types
            ];
            
            // Add MySQL-specific options only for MySQL
            if (!defined('DB_TYPE') || DB_TYPE !== 'sqlite') {
                $this->options[PDO::MYSQL_ATTR_FOUND_ROWS] = true;
                $this->options[PDO::MYSQL_ATTR_INIT_COMMAND] = "SET sql_mode='STRICT_TRANS_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION'";
            }
        } else {
            // Insecure options (for vulnerability demonstration)
            $this->options = [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_SILENT, // Hide errors (information disclosure)
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => true, // Vulnerable to some injection types
            ];
        }
    }
    
    /**
     * Establish database connection
     */
    private function connect() {
        try {
            // Support both MySQL and SQLite
            if (defined('DB_TYPE') && DB_TYPE === 'sqlite') {
                $dsn = "sqlite:" . $this->dbname;
                $this->pdo = new PDO($dsn, null, null, $this->options);
            } else {
                $dsn = "mysql:host={$this->host};dbname={$this->dbname};charset=" . DB_CHARSET;
                $this->pdo = new PDO($dsn, $this->username, $this->password, $this->options);
            }
            
            if (DEBUG_MODE) {
                error_log("Database connected successfully");
            }
            
        } catch (PDOException $e) {
            if (DEBUG_MODE) {
                // In debug mode, show detailed error (potential information disclosure)
                throw new Exception("Database connection failed: " . $e->getMessage());
            } else {
                // In production, log error and show generic message
                error_log("Database connection failed: " . $e->getMessage());
                throw new Exception("Database connection failed");
            }
        }
    }
    
    /**
     * Initialize database with sample tables and data
     */
    private function initializeDatabase() {
        try {
            if (defined('DB_TYPE') && DB_TYPE === 'sqlite') {
                // SQLite compatible schema
                $this->pdo->exec("
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username VARCHAR(50) UNIQUE NOT NULL,
                        email VARCHAR(100) UNIQUE NOT NULL,
                        password VARCHAR(255) NOT NULL,
                        role VARCHAR(10) DEFAULT 'user' CHECK (role IN ('user', 'admin')),
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        is_active BOOLEAN DEFAULT 1
                    )
                ");
                
                $this->pdo->exec("
                    CREATE TABLE IF NOT EXISTS posts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        title VARCHAR(200) NOT NULL,
                        content TEXT,
                        status VARCHAR(10) DEFAULT 'draft' CHECK (status IN ('draft', 'published')),
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                    )
                ");
                
                $this->pdo->exec("
                    CREATE TABLE IF NOT EXISTS security_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_type VARCHAR(50) NOT NULL,
                        user_id INTEGER NULL,
                        ip_address VARCHAR(45),
                        user_agent TEXT,
                        details TEXT,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ");
            } else {
                // MySQL schema
                $this->pdo->exec("
                    CREATE TABLE IF NOT EXISTS users (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        username VARCHAR(50) UNIQUE NOT NULL,
                        email VARCHAR(100) UNIQUE NOT NULL,
                        password VARCHAR(255) NOT NULL,
                        role ENUM('user', 'admin') DEFAULT 'user',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                        is_active BOOLEAN DEFAULT TRUE
                    )
                ");
                
                $this->pdo->exec("
                    CREATE TABLE IF NOT EXISTS posts (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        user_id INT NOT NULL,
                        title VARCHAR(200) NOT NULL,
                        content TEXT,
                        status ENUM('draft', 'published') DEFAULT 'draft',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                    )
                ");
                
                $this->pdo->exec("
                    CREATE TABLE IF NOT EXISTS security_logs (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        event_type VARCHAR(50) NOT NULL,
                        user_id INT NULL,
                        ip_address VARCHAR(45),
                        user_agent TEXT,
                        details JSON,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        INDEX idx_event_type (event_type),
                        INDEX idx_created_at (created_at)
                    )
                ");
            }
            
            // Insert sample data if tables are empty
            $this->insertSampleData();
            
        } catch (PDOException $e) {
            if (DEBUG_MODE) {
                error_log("Database initialization error: " . $e->getMessage());
            }
        }
    }
    
    /**
     * Insert sample data for testing
     */
    private function insertSampleData() {
        // Check if data already exists
        $userCount = $this->query("SELECT COUNT(*) as count FROM users")->fetch()['count'];
        
        if ($userCount == 0) {
            // Insert sample users
            $this->insert('users', [
                'username' => 'admin',
                'email' => 'admin@example.com',
                'password' => password_hash('admin123', PASSWORD_DEFAULT),
                'role' => 'admin'
            ]);
            
            $this->insert('users', [
                'username' => 'testuser',
                'email' => 'test@example.com',
                'password' => password_hash('password', PASSWORD_DEFAULT),
                'role' => 'user'
            ]);
            
            // Insert sample posts
            $this->insert('posts', [
                'user_id' => 1,
                'title' => 'Welcome to Bug Bounty Learning',
                'content' => 'This is a sample post for testing purposes.',
                'status' => 'published'
            ]);
            
            $this->insert('posts', [
                'user_id' => 2,
                'title' => 'SQL Injection Testing Post',
                'content' => 'Test post for SQL injection demonstrations.',
                'status' => 'published'
            ]);
            
            if (DEBUG_MODE) {
                error_log("Sample data inserted successfully");
            }
        }
    }
    
    /**
     * SECURE DATABASE METHODS
     * These use prepared statements and proper error handling
     */
    
    /**
     * Execute a secure prepared query
     */
    public function query($sql, $params = []) {
        $startTime = microtime(true);
        
        try {
            $stmt = $this->pdo->prepare($sql);
            $stmt->execute($params);
            
            $executionTime = microtime(true) - $startTime;
            
            // Log query for debugging
            logSQLQuery($sql, $params, $executionTime);
            
            return $stmt;
            
        } catch (PDOException $e) {
            $this->handleDatabaseError($e, $sql, $params);
        }
    }
    
    /**
     * Secure SELECT operation
     */
    public function select($table, $columns = '*', $where = [], $options = []) {
        $sql = "SELECT $columns FROM $table";
        $params = [];
        
        if (!empty($where)) {
            $conditions = [];
            foreach ($where as $column => $value) {
                $conditions[] = "$column = ?";
                $params[] = $value;
            }
            $sql .= " WHERE " . implode(' AND ', $conditions);
        }
        
        // Add additional options
        if (isset($options['order_by'])) {
            $sql .= " ORDER BY " . $options['order_by'];
        }
        
        if (isset($options['limit'])) {
            $sql .= " LIMIT " . (int)$options['limit'];
        }
        
        return $this->query($sql, $params)->fetchAll();
    }
    
    /**
     * Secure INSERT operation
     */
    public function insert($table, $data) {
        $columns = implode(',', array_keys($data));
        $placeholders = implode(',', array_fill(0, count($data), '?'));
        
        $sql = "INSERT INTO $table ($columns) VALUES ($placeholders)";
        $this->query($sql, array_values($data));
        
        return $this->pdo->lastInsertId();
    }
    
    /**
     * Secure UPDATE operation
     */
    public function update($table, $data, $where) {
        $setParts = [];
        $params = [];
        
        foreach ($data as $column => $value) {
            $setParts[] = "$column = ?";
            $params[] = $value;
        }
        
        $whereParts = [];
        foreach ($where as $column => $value) {
            $whereParts[] = "$column = ?";
            $params[] = $value;
        }
        
        $sql = "UPDATE $table SET " . implode(', ', $setParts) . " WHERE " . implode(' AND ', $whereParts);
        return $this->query($sql, $params);
    }
    
    /**
     * Secure DELETE operation
     */
    public function delete($table, $where) {
        $conditions = [];
        $params = [];
        
        foreach ($where as $column => $value) {
            $conditions[] = "$column = ?";
            $params[] = $value;
        }
        
        $sql = "DELETE FROM $table WHERE " . implode(' AND ', $conditions);
        return $this->query($sql, $params);
    }
    
    /**
     * Get user by ID (secure)
     */
    public function getUserById($id) {
        return $this->query("SELECT * FROM users WHERE id = ?", [$id])->fetch();
    }
    
    /**
     * Get user by username (secure)
     */
    public function getUserByUsername($username) {
        return $this->query("SELECT * FROM users WHERE username = ?", [$username])->fetch();
    }
    
    /**
     * Get posts with pagination (secure)
     */
    public function getPosts($limit = 10, $offset = 0) {
        $sql = "SELECT p.*, u.username FROM posts p 
                JOIN users u ON p.user_id = u.id 
                WHERE p.status = 'published' 
                ORDER BY p.created_at DESC 
                LIMIT ? OFFSET ?";
        return $this->query($sql, [$limit, $offset])->fetchAll();
    }
    
    /**
     * VULNERABLE DATABASE METHODS
     * These demonstrate SQL injection vulnerabilities
     */
    
    /**
     * Vulnerable query (SQL injection)
     */
    public function vulnerableQuery($sql) {
        if (!$this->secureMode) {
            // WARNING: This is vulnerable to SQL injection
            try {
                $result = $this->pdo->query($sql);
                return $result;
            } catch (PDOException $e) {
                if (DEBUG_MODE) {
                    echo "SQL Error: " . $e->getMessage();
                }
                return false;
            }
        } else {
            throw new Exception("Vulnerable queries not allowed in secure mode");
        }
    }
    
    /**
     * Vulnerable user search (SQL injection)
     */
    public function vulnerableUserSearch($searchTerm) {
        if (!$this->secureMode) {
            // WARNING: SQL injection vulnerability
            $sql = "SELECT * FROM users WHERE username LIKE '%$searchTerm%' OR email LIKE '%$searchTerm%'";
            return $this->vulnerableQuery($sql);
        } else {
            // Secure version
            $sql = "SELECT * FROM users WHERE username LIKE ? OR email LIKE ?";
            $searchPattern = "%$searchTerm%";
            return $this->query($sql, [$searchPattern, $searchPattern])->fetchAll();
        }
    }
    
    /**
     * Vulnerable login check (SQL injection)
     */
    public function vulnerableLogin($username, $password) {
        if (!$this->secureMode) {
            // WARNING: SQL injection vulnerability
            $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
            $result = $this->vulnerableQuery($sql);
            return $result ? $result->fetch() : false;
        } else {
            // Secure version with password hashing
            $user = $this->getUserByUsername($username);
            if ($user && password_verify($password, $user['password'])) {
                return $user;
            }
            return false;
        }
    }
    
    /**
     * Transaction handling
     */
    public function beginTransaction() {
        return $this->pdo->beginTransaction();
    }
    
    public function commit() {
        return $this->pdo->commit();
    }
    
    public function rollback() {
        return $this->pdo->rollback();
    }
    
    /**
     * Transaction wrapper
     */
    public function transaction($callback) {
        try {
            $this->beginTransaction();
            $result = $callback($this);
            $this->commit();
            return $result;
        } catch (Exception $e) {
            $this->rollback();
            throw $e;
        }
    }
    
    /**
     * Error handling
     */
    private function handleDatabaseError($exception, $sql, $params = []) {
        $errorInfo = [
            'message' => $exception->getMessage(),
            'sql' => $sql,
            'params' => $params,
            'file' => $exception->getFile(),
            'line' => $exception->getLine()
        ];
        
        // Log error
        error_log("Database Error: " . json_encode($errorInfo));
        
        // Log security event for potential injection attempts
        if (strpos(strtoupper($sql), 'UNION') !== false || 
            strpos(strtoupper($sql), 'DROP') !== false ||
            strpos(strtoupper($sql), 'DELETE') !== false) {
            logSecurityEvent('suspicious_sql_query', $errorInfo);
        }
        
        if (DEBUG_MODE) {
            throw new Exception("Database Error: " . $exception->getMessage() . " SQL: $sql");
        } else {
            throw new Exception("Database operation failed");
        }
    }
    
    /**
     * Get database statistics
     */
    public function getStats() {
        $stats = [];
        
        try {
            $stats['users_count'] = $this->query("SELECT COUNT(*) as count FROM users")->fetch()['count'];
            $stats['posts_count'] = $this->query("SELECT COUNT(*) as count FROM posts")->fetch()['count'];
            $stats['published_posts'] = $this->query("SELECT COUNT(*) as count FROM posts WHERE status = 'published'")->fetch()['count'];
            $stats['active_users'] = $this->query("SELECT COUNT(*) as count FROM users WHERE is_active = 1")->fetch()['count'];
        } catch (Exception $e) {
            $stats['error'] = 'Unable to retrieve statistics';
        }
        
        return $stats;
    }
    
    /**
     * Get connection info for debugging
     */
    public function getConnectionInfo() {
        return [
            'host' => $this->host,
            'database' => $this->dbname,
            'username' => $this->username,
            'secure_mode' => $this->secureMode,
            'server_info' => $this->pdo->getAttribute(PDO::ATTR_SERVER_INFO),
            'server_version' => $this->pdo->getAttribute(PDO::ATTR_SERVER_VERSION),
            'connection_status' => $this->pdo->getAttribute(PDO::ATTR_CONNECTION_STATUS)
        ];
    }
    
    /**
     * Close database connection
     */
    public function close() {
        $this->pdo = null;
    }
    
    /**
     * Get PDO instance (use with caution)
     */
    public function getPDO() {
        return $this->pdo;
    }
}

/**
 * Global Database Helper Functions
 */

/**
 * Get database instance
 */
function db($secureMode = true) {
    static $instance = null;
    
    if ($instance === null) {
        $instance = new Database($secureMode);
    }
    
    return $instance;
}

/**
 * Quick database query
 */
function dbQuery($sql, $params = []) {
    return db()->query($sql, $params);
}

/**
 * SQL Injection Testing Functions
 */

/**
 * Test SQL injection vulnerability
 */
function testSQLInjection($input) {
    echo "<div class='vulnerability-test'>";
    echo "<h3>SQL Injection Test</h3>";
    echo "<p><strong>Input:</strong> " . htmlspecialchars($input) . "</p>";
    
    // Secure query
    echo "<h4>Secure Query (Prepared Statement):</h4>";
    try {
        $secureDb = new Database(true);
        $result = $secureDb->vulnerableUserSearch($input);
        echo "<p>✅ Protected against SQL injection</p>";
    } catch (Exception $e) {
        echo "<p>❌ Error: " . htmlspecialchars($e->getMessage()) . "</p>";
    }
    
    // Vulnerable query (only in debug mode)
    if (DEBUG_MODE) {
        echo "<h4>Vulnerable Query (String Concatenation):</h4>";
        try {
            $vulnerableDb = new Database(false);
            $result = $vulnerableDb->vulnerableUserSearch($input);
            echo "<p>⚠️ Vulnerable to SQL injection</p>";
        } catch (Exception $e) {
            echo "<p>❌ Error: " . htmlspecialchars($e->getMessage()) . "</p>";
        }
    }
    
    echo "</div>";
}

/**
 * Database security demonstration
 */
function databaseSecurityDemo() {
    echo "<div class='security-demo'>";
    echo "<h3>Database Security Demonstration</h3>";
    
    $db = db();
    $info = $db->getConnectionInfo();
    $stats = $db->getStats();
    
    echo "<h4>Connection Info:</h4>";
    echo "<ul>";
    echo "<li>Database: " . htmlspecialchars($info['database']) . "</li>";
    echo "<li>Server Version: " . htmlspecialchars($info['server_version']) . "</li>";
    echo "<li>Secure Mode: " . ($info['secure_mode'] ? 'Yes' : 'No') . "</li>";
    echo "</ul>";
    
    echo "<h4>Database Statistics:</h4>";
    echo "<ul>";
    foreach ($stats as $key => $value) {
        echo "<li>" . ucfirst(str_replace('_', ' ', $key)) . ": " . htmlspecialchars($value) . "</li>";
    }
    echo "</ul>";
    
    echo "</div>";
}

/**
 * LEARNING NOTES FOR BUG BOUNTY HUNTERS:
 * 
 * 1. SQL Injection Testing:
 *    - Test with single quotes (') to break string context
 *    - Try UNION-based injection: ' UNION SELECT 1,2,3--
 *    - Boolean-based blind: ' AND 1=1-- vs ' AND 1=2--
 *    - Time-based blind: ' AND SLEEP(5)--
 *    - Error-based: ' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION(),0x7e))--
 * 
 * 2. Common Injection Points:
 *    - Login forms (username/password fields)
 *    - Search functionality
 *    - URL parameters (?id=1)
 *    - POST data
 *    - HTTP headers (rare but possible)
 * 
 * 3. Testing Methodology:
 *    - Identify all input points that interact with database
 *    - Test each parameter individually
 *    - Use different payloads for different database types
 *    - Look for error messages that reveal database structure
 * 
 * 4. Protection Mechanisms:
 *    - Prepared statements (best defense)
 *    - Input validation and sanitization
 *    - Least privilege database accounts
 *    - WAF (Web Application Firewall) detection
 * 
 * 5. Advanced Techniques:
 *    - Second-order SQL injection
 *    - NoSQL injection (if using NoSQL databases)
 *    - ORM injection vulnerabilities
 *    - Stored procedure injection
 * 
 * 6. Tools for Testing:
 *    - SQLMap (automated SQL injection tool)
 *    - Burp Suite extensions
 *    - Manual testing with Burp/OWASP ZAP
 *    - Custom payloads based on application context
 */
?>