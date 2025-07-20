#!/bin/bash

echo "=============================================="
echo "  PHP Bug Bounty Learning Environment"
echo "  Quick Installation Script"
echo "=============================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    print_warning "Running as root. Consider using a non-root user for security."
fi

# Step 1: Check operating system
echo "Step 1: Checking operating system..."
OS=$(uname -s)
case $OS in
    Linux*)
        print_status "Linux detected"
        PACKAGE_MANAGER=""
        if command -v apt-get &> /dev/null; then
            PACKAGE_MANAGER="apt-get"
        elif command -v yum &> /dev/null; then
            PACKAGE_MANAGER="yum"
        elif command -v dnf &> /dev/null; then
            PACKAGE_MANAGER="dnf"
        elif command -v pacman &> /dev/null; then
            PACKAGE_MANAGER="pacman"
        fi
        ;;
    Darwin*)
        print_status "macOS detected"
        if command -v brew &> /dev/null; then
            PACKAGE_MANAGER="brew"
        else
            print_warning "Homebrew not found. Please install Homebrew first: https://brew.sh/"
        fi
        ;;
    *)
        print_warning "Unsupported operating system: $OS"
        ;;
esac

# Step 2: Check PHP installation
echo ""
echo "Step 2: Checking PHP installation..."
if command -v php &> /dev/null; then
    PHP_VERSION=$(php -v | head -n1 | cut -d' ' -f2 | cut -d'-' -f1)
    print_status "PHP $PHP_VERSION found"
    
    # Check PHP version
    MIN_VERSION="8.0.0"
    if php -r "exit(version_compare(PHP_VERSION, '$MIN_VERSION', '<'))"; then
        print_status "PHP version is compatible (>= $MIN_VERSION)"
    else
        print_error "PHP version $PHP_VERSION is too old. Please upgrade to PHP $MIN_VERSION or higher"
        exit 1
    fi
else
    print_error "PHP not found"
    echo ""
    echo "Installing PHP..."
    
    case $PACKAGE_MANAGER in
        apt-get)
            sudo apt-get update
            sudo apt-get install -y php php-mysql php-mbstring php-json php-session
            ;;
        yum|dnf)
            sudo $PACKAGE_MANAGER install -y php php-mysqlnd php-mbstring php-json
            ;;
        pacman)
            sudo pacman -S php php-mysql
            ;;
        brew)
            brew install php
            ;;
        *)
            print_error "Cannot automatically install PHP. Please install manually."
            exit 1
            ;;
    esac
fi

# Step 3: Check required PHP extensions
echo ""
echo "Step 3: Checking PHP extensions..."
REQUIRED_EXTENSIONS=("pdo" "pdo_mysql" "mbstring" "json" "session")
MISSING_EXTENSIONS=()

for ext in "${REQUIRED_EXTENSIONS[@]}"; do
    if php -m | grep -q "^$ext$"; then
        print_status "$ext extension loaded"
    else
        print_error "$ext extension missing"
        MISSING_EXTENSIONS+=($ext)
    fi
done

if [ ${#MISSING_EXTENSIONS[@]} -ne 0 ]; then
    print_error "Missing extensions: ${MISSING_EXTENSIONS[*]}"
    echo ""
    echo "Installing missing extensions..."
    
    case $PACKAGE_MANAGER in
        apt-get)
            for ext in "${MISSING_EXTENSIONS[@]}"; do
                case $ext in
                    pdo|pdo_mysql)
                        sudo apt-get install -y php-mysql
                        ;;
                    mbstring)
                        sudo apt-get install -y php-mbstring
                        ;;
                    json)
                        sudo apt-get install -y php-json
                        ;;
                esac
            done
            ;;
        yum|dnf)
            for ext in "${MISSING_EXTENSIONS[@]}"; do
                case $ext in
                    pdo|pdo_mysql)
                        sudo $PACKAGE_MANAGER install -y php-mysqlnd
                        ;;
                    mbstring)
                        sudo $PACKAGE_MANAGER install -y php-mbstring
                        ;;
                esac
            done
            ;;
        *)
            print_warning "Please install missing PHP extensions manually"
            ;;
    esac
fi

# Step 4: Check MySQL/MariaDB
echo ""
echo "Step 4: Checking database server..."
if command -v mysql &> /dev/null; then
    print_status "MySQL client found"
elif command -v mariadb &> /dev/null; then
    print_status "MariaDB client found"
else
    print_warning "MySQL/MariaDB client not found"
    echo ""
    echo "Installing MySQL/MariaDB..."
    
    case $PACKAGE_MANAGER in
        apt-get)
            sudo apt-get install -y mysql-server
            ;;
        yum|dnf)
            sudo $PACKAGE_MANAGER install -y mariadb-server mariadb
            sudo systemctl start mariadb
            sudo systemctl enable mariadb
            ;;
        pacman)
            sudo pacman -S mariadb
            sudo mysql_install_db --user=mysql --basedir=/usr --datadir=/var/lib/mysql
            sudo systemctl start mariadb
            sudo systemctl enable mariadb
            ;;
        brew)
            brew install mysql
            brew services start mysql
            ;;
        *)
            print_warning "Please install MySQL/MariaDB manually"
            ;;
    esac
fi

# Step 5: Create necessary directories
echo ""
echo "Step 5: Creating directories..."
DIRECTORIES=("uploads" "logs")

for dir in "${DIRECTORIES[@]}"; do
    if [ ! -d "$dir" ]; then
        mkdir -p "$dir"
        chmod 755 "$dir"
        print_status "Created directory: $dir"
    else
        print_status "Directory already exists: $dir"
    fi
done

# Step 6: Set permissions
echo ""
echo "Step 6: Setting permissions..."
chmod 755 uploads logs
print_status "Permissions set for directories"

# Step 7: Check if setup.php exists
echo ""
echo "Step 7: Checking setup script..."
if [ -f "setup.php" ]; then
    print_status "Setup script found"
else
    print_error "setup.php not found. Please ensure you have all project files."
    exit 1
fi

# Final instructions
echo ""
echo "=============================================="
echo "  Installation Complete!"
echo "=============================================="
echo ""
echo "Next steps:"
echo "1. Run the setup script:"
echo "   php setup.php"
echo ""
echo "2. Start the development server:"
echo "   php -S localhost:8080 -t ."
echo ""
echo "3. Open your browser and visit:"
echo "   http://localhost:8080"
echo ""
echo "Security Notes:"
echo "⚠️  This application contains intentional vulnerabilities"
echo "⚠️  Only use in a secure, isolated environment"
echo "⚠️  Never deploy to production servers"
echo ""
echo "For help:"
echo "- Check the README.md file"
echo "- Visit the project documentation"
echo "- Enable DEBUG_MODE in config/app.php for detailed errors"
echo ""
print_status "Installation script completed successfully!"
echo ""

