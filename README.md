# PHP Bug Bounty Learning Environment

This project is designed to help you understand PHP web development fundamentals and common security vulnerabilities from a bug bounty perspective.

## Learning Objectives

### Core PHP Web Development Concepts
- **HTTP Workflow**: How browsers create requests and web apps handle them
- **Routing**: URL routing and parameter extraction
- **Templating**: Template engines with secure and insecure rendering
- **Sessions & Cookies**: Session management and security
- **Form Handling**: Input validation and sanitization
- **Error Handling**: Debugging vs production error handling

### Security Vulnerabilities (For Educational Purposes)
- SQL Injection
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Session Fixation/Hijacking
- Information Disclosure
- Input Validation Bypass

## Project Structure

```
/
├── index.php              # Main entry point - HTTP workflow demo
├── config/
│   └── app.php           # Application configuration
├── core/
│   ├── Router.php        # URL routing system
│   ├── Template.php      # Template engine
│   ├── Session.php       # Session management
│   └── Database.php      # Database abstraction
├── controllers/
│   ├── HomeController.php
│   ├── AuthController.php
│   └── VulnController.php # Vulnerability demonstrations
├── views/
│   ├── layouts/
│   │   └── main.php      # Main layout template
│   └── home/
│       └── index.php     # Home page view
├── middleware/
│   ├── AuthMiddleware.php
│   └── CSRFMiddleware.php
├── public/
│   └── assets/           # CSS, JS, images
└── setup.php            # Environment setup script
```

## Quick Start

1. **Setup Environment**:
   ```bash
   php setup.php
   ```

2. **Start Development Server**:
   ```bash
   php -S localhost:8080 -t .
   ```

3. **Visit Application**:
   Open http://localhost:8080 in your browser

## Learning Path

### 1. HTTP Workflow Understanding
- Start with `index.php` to see how HTTP requests are handled
- Examine how routing works in `core/Router.php`
- Understand middleware execution order

### 2. Template Security
- Compare secure vs insecure template rendering in `core/Template.php`
- Test XSS vulnerabilities in template outputs

### 3. Session Management
- Learn session lifecycle in `core/Session.php`
- Test session fixation and hijacking prevention

### 4. Database Interactions
- Understand prepared statements vs raw queries in `core/Database.php`
- Practice SQL injection testing

### 5. Form Handling
- Examine input validation and CSRF protection
- Test various input validation bypasses

## Vulnerability Examples

### SQL Injection
```php
// Vulnerable (for learning)
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];

// Secure
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$_GET['id']]);
```

### XSS Prevention
```php
// Vulnerable (for learning)
echo $_GET['message'];

// Secure
echo htmlspecialchars($_GET['message'], ENT_QUOTES, 'UTF-8');
```

### CSRF Protection
```php
// Generate token
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));

// Validate token
if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
    die('CSRF token mismatch');
}
```

## Testing Tools

### Manual Testing
- Browser Developer Tools (Network tab)
- Burp Suite Community Edition
- OWASP ZAP

### Automated Testing
```bash
# SQL injection testing
sqlmap -u "http://localhost:8080/user.php?id=1"

# XSS testing
python3 -m http.server 8888 # For XSS payloads
```

## Bug Bounty Methodology

1. **Reconnaissance**: Map all endpoints and parameters
2. **Input Validation**: Test all input points
3. **Authentication**: Test session management
4. **Authorization**: Test access controls
5. **Data Validation**: Test SQL injection, XSS
6. **Business Logic**: Test application workflow

## Security Headers Testing

```bash
curl -I http://localhost:8080
```

Look for missing security headers:
- `X-Content-Type-Options`
- `X-Frame-Options`
- `X-XSS-Protection`
- `Content-Security-Policy`

## Environment Variables

Create `.env` file for sensitive configuration:
```
DB_HOST=localhost
DB_NAME=bugbounty_learning
DB_USER=root
DB_PASS=
DEBUG_MODE=true
```

## Contributing

This is a learning environment. Feel free to:
- Add new vulnerability examples
- Improve documentation
- Add more testing scenarios
- Enhance the UI/UX

## Disclaimer

This application contains intentional security vulnerabilities for educational purposes. 
**Never deploy this to a production environment or public server.**

## Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [Bug Bounty Methodology](https://github.com/jhaddix/tbhm)
- [PHP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html)