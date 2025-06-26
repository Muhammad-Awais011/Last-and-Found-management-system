<?php
// config.php - Database configuration
class Database {
    private $host = 'localhost';
    private $db_name = 'lost_found_db';
    private $username = 'root';
    private $password = '';
    public $conn;

    public function getConnection() {
        $this->conn = null;
        try {
            $this->conn = new PDO("mysql:host=" . $this->host . ";dbname=" . $this->db_name, 
                                $this->username, $this->password);
            $this->conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        } catch(PDOException $exception) {
            echo "Connection error: " . $exception->getMessage();
        }
        return $this->conn;
    }
}

// Database setup script
function setupDatabase() {
    $database = new Database();
    $db = $database->getConnection();
    
    // Create users table
    $query = "CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        full_name VARCHAR(100) NOT NULL,
        phone VARCHAR(20),
        role ENUM('admin', 'user') DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )";
    $db->exec($query);
    
    // Create items table
    $query = "CREATE TABLE IF NOT EXISTS items (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        title VARCHAR(200) NOT NULL,
        description TEXT NOT NULL,
        category VARCHAR(50) NOT NULL,
        type ENUM('lost', 'found') NOT NULL,
        location VARCHAR(200) NOT NULL,
        date_lost_found DATE NOT NULL,
        status ENUM('active', 'resolved', 'closed') DEFAULT 'active',
        contact_info VARCHAR(200),
        image_path VARCHAR(500),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )";
    $db->exec($query);
    
    // Create matches table
    $query = "CREATE TABLE IF NOT EXISTS matches (
        id INT AUTO_INCREMENT PRIMARY KEY,
        lost_item_id INT NOT NULL,
        found_item_id INT NOT NULL,
        status ENUM('pending', 'confirmed', 'rejected') DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (lost_item_id) REFERENCES items(id) ON DELETE CASCADE,
        FOREIGN KEY (found_item_id) REFERENCES items(id) ON DELETE CASCADE
    )";
    $db->exec($query);
    
    
    // Create admin user if not exists
    $query = "SELECT COUNT(*) FROM users WHERE role = 'admin'";
    $stmt = $db->prepare($query);
    $stmt->execute();
    
    if ($stmt->fetchColumn() == 0) {
        $query = "INSERT INTO users (username, email, password, full_name, role) 
                  VALUES ('admin', 'admin@lostfound.com', ?, 'System Administrator', 'admin')";
        $stmt = $db->prepare($query);
        $stmt->execute([password_hash('admin123', PASSWORD_DEFAULT)]);
    }
}

session_start();

// Auto-setup database on first run
if (!isset($_SESSION['db_setup'])) {
    setupDatabase();
    $_SESSION['db_setup'] = true;
}

// Helper functions
function isLoggedIn() {
    return isset($_SESSION['user_id']);
}

function isAdmin() {
    return isset($_SESSION['role']) && $_SESSION['role'] === 'admin';
}

function redirectIfNotLoggedIn() {
    if (!isLoggedIn()) {
        header('Location: ?page=login');
        exit();
    }
}

function sanitizeInput($data) {
    return htmlspecialchars(strip_tags(trim($data)));
}

// Handle file uploads
function handleImageUpload($file) {
    if (!isset($file) || $file['error'] !== UPLOAD_ERR_OK) {
        return null;
    }
    
    $uploadDir = 'uploads/';
    if (!is_dir($uploadDir)) {
        mkdir($uploadDir, 0777, true);
    }
    
    $allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
    if (!in_array($file['type'], $allowedTypes)) {
        return null;
    }
    
    $fileName = uniqid() . '_' . basename($file['name']);
    $targetPath = $uploadDir . $fileName;
    
    if (move_uploaded_file($file['tmp_name'], $targetPath)) {
        return $targetPath;
    }
    
    return null;
}

// Get current page
$page = $_GET['page'] ?? 'home';

// HANDLE ALL REDIRECTS AND POST PROCESSING BEFORE ANY HTML OUTPUT
// ================================================================

// Handle logout
if ($page === 'logout') {
    session_destroy();
    header('Location: ?page=home');
    exit();
}

// For admin page access control
if ($page === 'admin' && !isAdmin()) {
    header('Location: ?page=home');
    exit();
}

// For pages requiring login
if (in_array($page, ['dashboard', 'report']) && !isLoggedIn()) {
    header('Location: ?page=login');
    exit();
}

// Handle login form submission
if ($page === 'login' && $_POST) {
    $username = sanitizeInput($_POST['username']);
    $password = $_POST['password'];
    
    if (!empty($username) && !empty($password)) {
        $database = new Database();
        $db = $database->getConnection();
        
        $query = "SELECT id, username, password, role, full_name FROM users WHERE username = ? OR email = ?";
        $stmt = $db->prepare($query);
        $stmt->execute([$username, $username]);
        
        if ($user = $stmt->fetch(PDO::FETCH_ASSOC)) {
            if (password_verify($password, $user['password'])) {
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['role'] = $user['role'];
                $_SESSION['full_name'] = $user['full_name'];
                
                header('Location: ?page=dashboard');
                exit();
            }
        }
    }
}

// Handle register form submission
if ($page === 'register' && $_POST) {
    $username = sanitizeInput($_POST['username']);
    $email = sanitizeInput($_POST['email']);
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm_password'];
    $full_name = sanitizeInput($_POST['full_name']);
    $phone = sanitizeInput($_POST['phone']);
    
    if (!empty($username) && !empty($email) && !empty($password) && !empty($full_name) 
        && $password === $confirm_password && strlen($password) >= 6) {
        
        $database = new Database();
        $db = $database->getConnection();
        
        // Check if username or email already exists
        $query = "SELECT COUNT(*) FROM users WHERE username = ? OR email = ?";
        $stmt = $db->prepare($query);
        $stmt->execute([$username, $email]);
        
        if ($stmt->fetchColumn() == 0) {
            $query = "INSERT INTO users (username, email, password, full_name, phone) VALUES (?, ?, ?, ?, ?)";
            $stmt = $db->prepare($query);
            
            if ($stmt->execute([$username, $email, password_hash($password, PASSWORD_DEFAULT), $full_name, $phone])) {
                // Registration successful, redirect to login
                header('Location: ?page=login&registered=1');
                exit();
            }
        }
    }
}

// Handle report item form submission
if ($page === 'report' && isLoggedIn() && $_POST) {
    $title = sanitizeInput($_POST['title']);
    $description = sanitizeInput($_POST['description']);
    $category = sanitizeInput($_POST['category']);
    $type = sanitizeInput($_POST['type']);
    $location = sanitizeInput($_POST['location']);
    $date_lost_found = sanitizeInput($_POST['date_lost_found']);
    $contact_info = sanitizeInput($_POST['contact_info']);
    
    if (!empty($title) && !empty($description) && !empty($category) && !empty($type) && !empty($location) && !empty($date_lost_found)) {
        $database = new Database();
        $db = $database->getConnection();
        
        $image_path = null;
        if (isset($_FILES['image']) && $_FILES['image']['error'] === UPLOAD_ERR_OK) {
            $image_path = handleImageUpload($_FILES['image']);
        }
        
        $query = "INSERT INTO items (user_id, title, description, category, type, location, date_lost_found, contact_info, image_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
        $stmt = $db->prepare($query);
        
        if ($stmt->execute([$_SESSION['user_id'], $title, $description, $category, $type, $location, $date_lost_found, $contact_info, $image_path])) {
            header('Location: ?page=dashboard&success=item_reported');
            exit();
        }
    }
}

// Handle admin actions
if ($page === 'admin' && isAdmin() && $_POST) {
    $database = new Database();
    $db = $database->getConnection();
    
    if (isset($_POST['delete_user'])) {
        $user_id = (int)$_POST['user_id'];
        if ($user_id !== $_SESSION['user_id']) {
            $query = "DELETE FROM users WHERE id = ? AND role != 'admin'";
            $stmt = $db->prepare($query);
            $stmt->execute([$user_id]);
        }
        header('Location: ?page=admin&success=user_deleted');
        exit();
    }
    
    if (isset($_POST['delete_item'])) {
        $item_id = (int)$_POST['item_id'];
        $query = "DELETE FROM items WHERE id = ?";
        $stmt = $db->prepare($query);
        $stmt->execute([$item_id]);
        header('Location: ?page=admin&success=item_deleted');
        exit();
    }
}

// Handle item status updates
if ($page === 'item' && $_POST && isset($_POST['update_status'])) {
    $item_id = $_GET['id'] ?? 0;
    
    if ($item_id && isLoggedIn()) {
        $database = new Database();
        $db = $database->getConnection();
        
        // Check if user owns the item or is admin
        $query = "SELECT user_id FROM items WHERE id = ?";
        $stmt = $db->prepare($query);
        $stmt->execute([$item_id]);
        $item_owner = $stmt->fetchColumn();
        
        if ($_SESSION['user_id'] == $item_owner || isAdmin()) {
            $new_status = sanitizeInput($_POST['status']);
            $query = "UPDATE items SET status = ? WHERE id = ?";
            $stmt = $db->prepare($query);
            $stmt->execute([$new_status, $item_id]);
            
            header('Location: ?page=item&id=' . $item_id . '&success=status_updated');
            exit();
        }
    }
}

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Lost & Found Management System</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <header>
        <nav class="container">
            <div class="logo">🔍 Lost & Found</div>
            <ul class="nav-links">
                <li><a href="?page=home">Home</a></li>
                <?php if (isLoggedIn()): ?>
                    <li><a href="?page=dashboard">Dashboard</a></li>
                    <li><a href="?page=browse">Browse Items</a></li>
                    <li><a href="?page=report">Report Item</a></li>
                    <?php if (isAdmin()): ?>
                        <li><a href="?page=admin">Admin</a></li>
                    <?php endif; ?>
                    <li><a href="?page=logout">Logout (<?php echo $_SESSION['username']; ?>)</a></li>
                <?php else: ?>
                    <li><a href="?page=login">Login</a></li>
                    <li><a href="?page=register">Register</a></li>
                <?php endif; ?>
            </ul>
        </nav>
    </header>

    <main>
        <div class="container">
            <?php
            // Page routing
            if ($page === 'logout') {
    session_destroy();
    header('Location: ?page=home');
    exit();
}

// For admin page access control
if ($page === 'admin' && !isAdmin()) {
    header('Location: ?page=home');
    exit();
}

// For pages requiring login
if (in_array($page, ['dashboard', 'report']) && !isLoggedIn()) {
    header('Location: ?page=login');
    exit();
}

// HOME PAGE
if ($page === 'home') {
    $database = new Database();
    $db = $database->getConnection();
    
    // Get statistics
    $query = "SELECT 
                COUNT(*) as total_items,
                SUM(CASE WHEN type = 'lost' THEN 1 ELSE 0 END) as lost_items,
                SUM(CASE WHEN type = 'found' THEN 1 ELSE 0 END) as found_items,
                SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) as resolved_items
              FROM items";
    $stmt = $db->prepare($query);
    $stmt->execute();
    $stats = $stmt->fetch(PDO::FETCH_ASSOC);
    
    echo '<div class="hero">
            <h1>Welcome to Lost & Found</h1>
            <p>Helping reunite people with their lost belongings</p>
            <a href="?page=browse" class="btn">Browse Items</a>
          </div>';
    
    echo '<div class="stats">
            <div class="stat-card">
                <div class="stat-number">' . $stats['total_items'] . '</div>
                <div class="stat-label">Total Items</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">' . $stats['lost_items'] . '</div>
                <div class="stat-label">Lost Items</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">' . $stats['found_items'] . '</div>
                <div class="stat-label">Found Items</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">' . $stats['resolved_items'] . '</div>
                <div class="stat-label">Resolved Cases</div>
            </div>
          </div>';
}

// LOGIN PAGE
if ($page === 'login') {
    $error = '';
    
    if ($_POST) {
        $username = sanitizeInput($_POST['username']);
        $password = $_POST['password'];
        
        if (empty($username) || empty($password)) {
            $error = 'Please fill in all fields.';
        } else {
            $database = new Database();
            $db = $database->getConnection();
            
            $query = "SELECT id, username, password, role, full_name FROM users WHERE username = ? OR email = ?";
            $stmt = $db->prepare($query);
            $stmt->execute([$username, $username]);
            
            if ($user = $stmt->fetch(PDO::FETCH_ASSOC)) {
                if (password_verify($password, $user['password'])) {
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['username'] = $user['username'];
                    $_SESSION['role'] = $user['role'];
                    $_SESSION['full_name'] = $user['full_name'];
                    
                    header('Location: ?page=dashboard');
                    exit();
                } else {
                    $error = 'Invalid password.';
                }
            } else {
                $error = 'User not found.';
            }
        }
    }
    
    echo '<div class="content-card" style="max-width: 400px; margin: 2rem auto;">
            <h2>Login</h2>';
    
    if ($error) {
        echo '<div class="alert alert-error">' . $error . '</div>';
    }
    
    echo '<form method="POST">
            <div class="form-group">
                <label>Username or Email:</label>
                <input type="text" name="username" required>
            </div>
            <div class="form-group">
                <label>Password:</label>
                <input type="password" name="password" required>
            </div>
            <button type="submit" class="btn">Login</button>
            <p style="margin-top: 1rem;">
                Don\'t have an account? <a href="?page=register">Register here</a>
            </p>
          </form>
          </div>';
}

// REGISTER PAGE
if ($page === 'register') {
    $error = '';
    $success = '';
    
    if ($_POST) {
        $username = sanitizeInput($_POST['username']);
        $email = sanitizeInput($_POST['email']);
        $password = $_POST['password'];
        $confirm_password = $_POST['confirm_password'];
        $full_name = sanitizeInput($_POST['full_name']);
        $phone = sanitizeInput($_POST['phone']);
        
        if (empty($username) || empty($email) || empty($password) || empty($full_name)) {
            $error = 'Please fill in all required fields.';
        } elseif ($password !== $confirm_password) {
            $error = 'Passwords do not match.';
        } elseif (strlen($password) < 6) {
            $error = 'Password must be at least 6 characters long.';
        } else {
            $database = new Database();
            $db = $database->getConnection();
            
            // Check if username or email already exists
            $query = "SELECT COUNT(*) FROM users WHERE username = ? OR email = ?";
            $stmt = $db->prepare($query);
            $stmt->execute([$username, $email]);
            
            if ($stmt->fetchColumn() > 0) {
                $error = 'Username or email already exists.';
            } else {
                $query = "INSERT INTO users (username, email, password, full_name, phone) VALUES (?, ?, ?, ?, ?)";
                $stmt = $db->prepare($query);
                
                if ($stmt->execute([$username, $email, password_hash($password, PASSWORD_DEFAULT), $full_name, $phone])) {
                    $success = 'Account created successfully! You can now login.';
                } else {
                    $error = 'Error creating account. Please try again.';
                }
            }
        }
    }
    
    echo '<div class="content-card" style="max-width: 500px; margin: 2rem auto;">
            <h2>Register</h2>';
    
    if ($error) {
        echo '<div class="alert alert-error">' . $error . '</div>';
    }
    
    if ($success) {
        echo '<div class="alert alert-success">' . $success . '</div>';
    }
    
    echo '<form method="POST">
            <div class="form-group">
                <label>Username: *</label>
                <input type="text" name="username" required>
            </div>
            <div class="form-group">
                <label>Email: *</label>
                <input type="email" name="email" required>
            </div>
            <div class="form-group">
                <label>Full Name: *</label>
                <input type="text" name="full_name" required>
            </div>
            <div class="form-group">
                <label>Phone:</label>
                <input type="tel" name="phone">
            </div>
            <div class="form-group">
                <label>Password: *</label>
                <input type="password" name="password" required>
            </div>
            <div class="form-group">
                <label>Confirm Password: *</label>
                <input type="password" name="confirm_password" required>
            </div>
            <button type="submit" class="btn">Register</button>
            <p style="margin-top: 1rem;">
                Already have an account? <a href="?page=login">Login here</a>
            </p>
          </form>
          </div>';
}

// DASHBOARD PAGE
if ($page === 'dashboard' && isLoggedIn()) {
    $database = new Database();
    $db = $database->getConnection();
    
    // Get user's items
    $query = "SELECT * FROM items WHERE user_id = ? ORDER BY created_at DESC";
    $stmt = $db->prepare($query);
    $stmt->execute([$_SESSION['user_id']]);
    $user_items = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    echo '<div class="content-card">
            <h2>Welcome, ' . $_SESSION['full_name'] . '</h2>
            <p>Manage your lost and found items from your dashboard.</p>
            
            <div style="margin: 2rem 0;">
                <a href="?page=report" class="btn">Report New Item</a>
                <a href="?page=browse" class="btn btn-secondary">Browse All Items</a>
            </div>
          </div>';
    
    echo '<div class="content-card">
            <h3>Your Items</h3>';
    
    if (empty($user_items)) {
        echo '<p>You haven\'t reported any items yet. <a href="?page=report">Report an item</a> to get started.</p>';
    } else {
        echo '<div class="table" style="overflow-x: auto;">
                <table class="table">
                    <thead>
                        <tr>
                            <th>Title</th>
                            <th>Type</th>
                            <th>Category</th>
                            <th>Status</th>
                            <th>Date</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>';
        
        foreach ($user_items as $item) {
            echo '<tr>
                    <td>' . htmlspecialchars($item['title']) . '</td>
                    <td><span class="item-status status-' . $item['type'] . '">' . ucfirst($item['type']) . '</span></td>
                    <td>' . htmlspecialchars($item['category']) . '</td>
                    <td><span class="item-status status-' . $item['status'] . '">' . ucfirst($item['status']) . '</span></td>
                    <td>' . date('M j, Y', strtotime($item['date_lost_found'])) . '</td>
                    <td>
                        <a href="?page=item&id=' . $item['id'] . '" class="btn" style="padding: 0.3rem 0.8rem; font-size: 0.8rem;">View</a>
                    </td>
                  </tr>';
        }
        
        echo '</tbody></table></div>';
    }
    
    echo '</div>';
}

// BROWSE PAGE
if ($page === 'browse') {
    $database = new Database();
    $db = $database->getConnection();
    
    // Handle search and filters
    $search = $_GET['search'] ?? '';
    $category = $_GET['category'] ?? '';
    $type = $_GET['type'] ?? '';
    $status = $_GET['status'] ?? 'active';
    
    $where_conditions = ['status = ?'];
    $params = [$status];
    
    if (!empty($search)) {
        $where_conditions[] = '(title LIKE ? OR description LIKE ?)';
        $params[] = "%$search%";
        $params[] = "%$search%";
    }
    
    if (!empty($category)) {
        $where_conditions[] = 'category = ?';
        $params[] = $category;
    }
    
    if (!empty($type)) {
        $where_conditions[] = 'type = ?';
        $params[] = $type;
    }
    
    $where_clause = implode(' AND ', $where_conditions);
    
    $query = "SELECT i.*, u.full_name, u.username 
              FROM items i 
              JOIN users u ON i.user_id = u.id 
              WHERE $where_clause 
              ORDER BY i.created_at DESC";
    
    $stmt = $db->prepare($query);
    $stmt->execute($params);
    $items = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Get categories for filter
    $query = "SELECT DISTINCT category FROM items ORDER BY category";
    $stmt = $db->prepare($query);
    $stmt->execute();
    $categories = $stmt->fetchAll(PDO::FETCH_COLUMN);
    
    echo '<div class="content-card">
            <h2>Browse Items</h2>
            
            <form class="search-container" method="GET">
                <input type="hidden" name="page" value="browse">
                <input type="text" name="search" placeholder="Search items..." value="' . htmlspecialchars($search) . '">
                <select name="category">
                    <option value="">All Categories</option>';
    
    foreach ($categories as $cat) {
        $selected = ($category === $cat) ? 'selected' : '';
        echo '<option value="' . htmlspecialchars($cat) . '" ' . $selected . '>' . htmlspecialchars($cat) . '</option>';
    }
    
    echo '</select>
                <select name="type">
                    <option value="">All Types</option>
                    <option value="lost"' . ($type === 'lost' ? ' selected' : '') . '>Lost</option>
                    <option value="found"' . ($type === 'found' ? ' selected' : '') . '>Found</option>
                </select>
                <select name="status">
                    <option value="active"' . ($status === 'active' ? ' selected' : '') . '>Active</option>
                    <option value="resolved"' . ($status === 'resolved' ? ' selected' : '') . '>Resolved</option>
                    <option value=""' . ($status === '' ? ' selected' : '') . '>All Status</option>
                </select>
                <button type="submit" class="btn">Search</button>
            </form>
          </div>';
    
    if (empty($items)) {
        echo '<div class="content-card">
                <p>No items found matching your criteria.</p>
              </div>';
    } else {
        echo '<div class="cards-grid">';
        
        foreach ($items as $item) {
            $image_src = !empty($item['image_path']) ? $item['image_path'] : 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMzAwIiBoZWlnaHQ9IjIwMCIgdmlld0JveD0iMCAwIDMwMCAyMDAiIGZpbGw9Im5vbmUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CjxyZWN0IHdpZHRoPSIzMDAiIGhlaWdodD0iMjAwIiBmaWxsPSIjRjhGOUZBIi8+CjxwYXRoIGQ9Ik0xNTAgMTAwQzE1MCA4My40MzE1IDE2My40MzEgNzAgMTgwIDcwQzE5Ni41NjkgNzAgMjEwIDgzLjQzMTUgMjEwIDEwMEMyMTAgMTE2LjU2OSAxOTYuNTY5IDEzMCAxODAgMTMwQzE2My40MzEgMTMwIDE1MCAxMTYuNTY5IDE1MCAxMDBaIiBmaWxsPSIjREREREREIi8+CjxwYXRoIGQ9Ik0xMjAgMTMwSDE4MFYxNTBIMTIwVjEzMFoiIGZpbGw9IiNEREREREQiLz4KPC9zdmc+';
            
            echo '<div class="item-card">
                    <img src="' . $image_src . '" alt="' . htmlspecialchars($item['title']) . '">
                    <div class="item-card-content">
                        <h3>' . htmlspecialchars($item['title']) . '</h3>
                        <p><strong>Type:</strong> <span class="item-status status-' . $item['type'] . '">' . ucfirst($item['type']) . '</span></p>
                        <p><strong>Category:</strong> ' . htmlspecialchars($item['category']) . '</p>
                        <p><strong>Location:</strong> ' . htmlspecialchars($item['location']) . '</p>
                        <p><strong>Date:</strong> ' . date('M j, Y', strtotime($item['date_lost_found'])) . '</p>
                        <p><strong>Status:</strong> <span class="item-status status-' . $item['status'] . '">' . ucfirst($item['status']) . '</span></p>
                        <p><strong>Reported by:</strong> ' . htmlspecialchars($item['full_name']) . '</p>
                        <a href="?page=item&id=' . $item['id'] . '" class="btn" style="margin-top: 1rem;">View Details</a>
                    </div>
                  </div>';
        }
        
        echo '</div>';
    }
}

// REPORT ITEM PAGE
if ($page === 'report' && isLoggedIn()) {
    $error = '';
    $success = '';
    
    if ($_POST) {
        $title = sanitizeInput($_POST['title']);
        $description = sanitizeInput($_POST['description']);
        $category = sanitizeInput($_POST['category']);
        $type = sanitizeInput($_POST['type']);
        $location = sanitizeInput($_POST['location']);
        $date_lost_found = sanitizeInput($_POST['date_lost_found']);
        $contact_info = sanitizeInput($_POST['contact_info']);
        
        if (empty($title) || empty($description) || empty($category) || empty($type) || empty($location) || empty($date_lost_found)) {
            $error = 'Please fill in all required fields.';
        } else {
            $database = new Database();
            $db = $database->getConnection();
            
            $image_path = null;
            if (isset($_FILES['image']) && $_FILES['image']['error'] === UPLOAD_ERR_OK) {
                $image_path = handleImageUpload($_FILES['image']);
            }
            
            $query = "INSERT INTO items (user_id, title, description, category, type, location, date_lost_found, contact_info, image_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
            $stmt = $db->prepare($query);
            
            if ($stmt->execute([$_SESSION['user_id'], $title, $description, $category, $type, $location, $date_lost_found, $contact_info, $image_path])) {
                $success = 'Item reported successfully!';
                // Clear form data
                $_POST = array();
            } else {
                $error = 'Error reporting item. Please try again.';
            }
        }
    }
    
    echo '<div class="content-card">
            <h2>Report Lost/Found Item</h2>';
    
    if ($error) {
        echo '<div class="alert alert-error">' . $error . '</div>';
    }
    
    if ($success) {
        echo '<div class="alert alert-success">' . $success . '</div>';
    }
    
    echo '<form method="POST" enctype="multipart/form-data">
            <div class="form-group">
                <label>Title: *</label>
                <input type="text" name="title" required value="' . ($_POST['title'] ?? '') . '">
            </div>
            
            <div class="form-group">
                <label>Type: *</label>
                <select name="type" required>
                    <option value="">Select Type</option>
                    <option value="lost"' . (($_POST['type'] ?? '') === 'lost' ? ' selected' : '') . '>Lost Item</option>
                    <option value="found"' . (($_POST['type'] ?? '') === 'found' ? ' selected' : '') . '>Found Item</option>
                </select>
            </div>
            
            <div class="form-group">
                <label>Category: *</label>
                <select name="category" required>
                    <option value="">Select Category</option>
                    <option value="Electronics"' . (($_POST['category'] ?? '') === 'Electronics' ? ' selected' : '') . '>Electronics</option>
                    <option value="Clothing"' . (($_POST['category'] ?? '') === 'Clothing' ? ' selected' : '') . '>Clothing</option>
                    <option value="Accessories"' . (($_POST['category'] ?? '') === 'Accessories' ? ' selected' : '') . '>Accessories</option>
                    <option value="Documents"' . (($_POST['category'] ?? '') === 'Documents' ? ' selected' : '') . '>Documents</option>
                    <option value="Keys"' . (($_POST['category'] ?? '') === 'Keys' ? ' selected' : '') . '>Keys</option>
                    <option value="Bags"' . (($_POST['category'] ?? '') === 'Bags' ? ' selected' : '') . '>Bags</option>
                    <option value="Sports Equipment"' . (($_POST['category'] ?? '') === 'Sports Equipment' ? ' selected' : '') . '>Sports Equipment</option>
                    <option value="Books"' . (($_POST['category'] ?? '') === 'Books' ? ' selected' : '') . '>Books</option>
                    <option value="Jewelry"' . (($_POST['category'] ?? '') === 'Jewelry' ? ' selected' : '') . '>Jewelry</option>
                    <option value="Other"' . (($_POST['category'] ?? '') === 'Other' ? ' selected' : '') . '>Other</option>
                </select>
            </div>
            
            <div class="form-group">
                <label>Description: *</label>
                <textarea name="description" rows="4" required placeholder="Provide detailed description including color, brand, distinctive features, etc.">' . ($_POST['description'] ?? '') . '</textarea>
            </div>
            
            <div class="form-group">
                <label>Location: *</label>
                <input type="text" name="location" required placeholder="Where was it lost/found?" value="' . ($_POST['location'] ?? '') . '">
            </div>
            
            <div class="form-group">
                <label>Date Lost/Found: *</label>
                <input type="date" name="date_lost_found" required value="' . ($_POST['date_lost_found'] ?? '') . '">
            </div>
            
            <div class="form-group">
                <label>Contact Information:</label>
                <input type="text" name="contact_info" placeholder="Phone number or email (optional)" value="' . ($_POST['contact_info'] ?? '') . '">
            </div>
            
            <div class="form-group">
                <label>Upload Image:</label>
                <input type="file" name="image" accept="image/*">
                <small style="color: #666;">Supported formats: JPG, PNG, GIF (optional)</small>
            </div>
            
            <button type="submit" class="btn">Report Item</button>
            <a href="?page=dashboard" class="btn btn-secondary">Cancel</a>
          </form>
          </div>';
}

// ITEM DETAIL PAGE
if ($page === 'item') {
    $item_id = $_GET['id'] ?? 0;
    
    if (!$item_id) {
        echo '<div class="content-card">
                <div class="alert alert-error">Invalid item ID.</div>
              </div>';
        return;
    }
    
    $database = new Database();
    $db = $database->getConnection();
    
    // Get item details
    $query = "SELECT i.*, u.full_name, u.username, u.email, u.phone 
              FROM items i 
              JOIN users u ON i.user_id = u.id 
              WHERE i.id = ?";
    $stmt = $db->prepare($query);
    $stmt->execute([$item_id]);
    $item = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$item) {
        echo '<div class="content-card">
                <div class="alert alert-error">Item not found.</div>
              </div>';
        return;
    }
    
    // Handle status updates (only by item owner or admin)
    if ($_POST && isset($_POST['update_status']) && (isLoggedIn() && ($_SESSION['user_id'] == $item['user_id'] || isAdmin()))) {
        $new_status = sanitizeInput($_POST['status']);
        
        $query = "UPDATE items SET status = ? WHERE id = ?";
        $stmt = $db->prepare($query);
        
        if ($stmt->execute([$new_status, $item_id])) {
            $item['status'] = $new_status;
            echo '<div class="alert alert-success">Status updated successfully!</div>';
        }
    }
    
    echo '<div class="content-card">
            <div style="display: grid; grid-template-columns: 1fr 2fr; gap: 2rem; align-items: start;">
                <div>';
    
    if (!empty($item['image_path'])) {
        echo '<img src="' . $item['image_path'] . '" alt="' . htmlspecialchars($item['title']) . '" style="width: 100%; border-radius: 8px; margin-bottom: 1rem;">';
    } else {
        echo '<div style="width: 100%; height: 250px; background: #f8f9fa; border-radius: 8px; display: flex; align-items: center; justify-content: center; margin-bottom: 1rem; color: #666;">
                📷 No Image Available
              </div>';
    }
    
    echo '</div>
                <div>
                    <h2>' . htmlspecialchars($item['title']) . '</h2>
                    <p><strong>Type:</strong> <span class="item-status status-' . $item['type'] . '">' . ucfirst($item['type']) . '</span></p>
                    <p><strong>Category:</strong> ' . htmlspecialchars($item['category']) . '</p>
                    <p><strong>Status:</strong> <span class="item-status status-' . $item['status'] . '">' . ucfirst($item['status']) . '</span></p>
                    <p><strong>Location:</strong> ' . htmlspecialchars($item['location']) . '</p>
                    <p><strong>Date:</strong> ' . date('F j, Y', strtotime($item['date_lost_found'])) . '</p>
                    <p><strong>Reported:</strong> ' . date('F j, Y g:i A', strtotime($item['created_at'])) . '</p>
                    
                    <h3>Description</h3>
                    <p>' . nl2br(htmlspecialchars($item['description'])) . '</p>
                    
                    <h3>Contact Information</h3>
                    <p><strong>Reported by:</strong> ' . htmlspecialchars($item['full_name']) . '</p>';
    
    if (!empty($item['contact_info'])) {
        echo '<p><strong>Contact:</strong> ' . htmlspecialchars($item['contact_info']) . '</p>';
    } else {
        echo '<p><strong>Contact:</strong> Contact through system</p>';
    }
    
    // Show contact details only to logged-in users
    if (isLoggedIn()) {
        echo '<p><strong>Email:</strong> ' . htmlspecialchars($item['email']) . '</p>';
        if (!empty($item['phone'])) {
            echo '<p><strong>Phone:</strong> ' . htmlspecialchars($item['phone']) . '</p>';
        }
    }
    
    echo '</div>
            </div>';
    
    // Status update form (only for item owner or admin)
    if (isLoggedIn() && ($_SESSION['user_id'] == $item['user_id'] || isAdmin())) {
        echo '<hr style="margin: 2rem 0;">
              <h3>Update Status</h3>
              <form method="POST" style="display: flex; gap: 1rem; align-items: center; flex-wrap: wrap;">
                <select name="status">
                    <option value="active"' . ($item['status'] === 'active' ? ' selected' : '') . '>Active</option>
                    <option value="resolved"' . ($item['status'] === 'resolved' ? ' selected' : '') . '>Resolved</option>
                    <option value="closed"' . ($item['status'] === 'closed' ? ' selected' : '') . '>Closed</option>
                </select>
                <button type="submit" name="update_status" class="btn">Update Status</button>
              </form>';
    }
    
    echo '</div>';
    
    echo '<div style="margin-top: 2rem;">
            <a href="?page=browse" class="btn btn-secondary">← Back to Browse</a>
          </div>';
}

// ADMIN PAGE
if ($page === 'admin' && isAdmin()) {
    $database = new Database();
    $db = $database->getConnection();
    
    // Handle user management actions
    if ($_POST) {
        if (isset($_POST['delete_user'])) {
            $user_id = (int)$_POST['user_id'];
            if ($user_id !== $_SESSION['user_id']) { // Can't delete self
                $query = "DELETE FROM users WHERE id = ? AND role != 'admin'";
                $stmt = $db->prepare($query);
                $stmt->execute([$user_id]);
                echo '<div class="alert alert-success">User deleted successfully!</div>';
            }
        }
        
        if (isset($_POST['delete_item'])) {
            $item_id = (int)$_POST['item_id'];
            $query = "DELETE FROM items WHERE id = ?";
            $stmt = $db->prepare($query);
            $stmt->execute([$item_id]);
            echo '<div class="alert alert-success">Item deleted successfully!</div>';
        }
    }
    
    // Get statistics
    $query = "SELECT 
                COUNT(*) as total_users,
                SUM(CASE WHEN role = 'admin' THEN 1 ELSE 0 END) as admin_users,
                SUM(CASE WHEN role = 'user' THEN 1 ELSE 0 END) as regular_users
              FROM users";
    $stmt = $db->prepare($query);
    $stmt->execute();
    $user_stats = $stmt->fetch(PDO::FETCH_ASSOC);
    
    $query = "SELECT 
                COUNT(*) as total_items,
                SUM(CASE WHEN type = 'lost' THEN 1 ELSE 0 END) as lost_items,
                SUM(CASE WHEN type = 'found' THEN 1 ELSE 0 END) as found_items,
                SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active_items,
                SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) as resolved_items
              FROM items";
    $stmt = $db->prepare($query);
    $stmt->execute();
    $item_stats = $stmt->fetch(PDO::FETCH_ASSOC);
    
    echo '<div class="content-card">
            <h2>Admin Dashboard</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-number">' . $user_stats['total_users'] . '</div>
                    <div class="stat-label">Total Users</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">' . $user_stats['regular_users'] . '</div>
                    <div class="stat-label">Regular Users</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">' . $item_stats['total_items'] . '</div>
                    <div class="stat-label">Total Items</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">' . $item_stats['active_items'] . '</div>
                    <div class="stat-label">Active Items</div>
                </div>
            </div>
          </div>';
    
    // Users Management
    $query = "SELECT * FROM users ORDER BY created_at DESC";
    $stmt = $db->prepare($query);
    $stmt->execute();
    $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    echo '<div class="content-card">
            <h3>User Management</h3>
            <div style="overflow-x: auto;">
                <table class="table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Username</th>
                            <th>Full Name</th>
                            <th>Email</th>
                            <th>Role</th>
                            <th>Registered</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>';
    
    foreach ($users as $user) {
        echo '<tr>
                <td>' . $user['id'] . '</td>
                <td>' . htmlspecialchars($user['username']) . '</td>
                <td>' . htmlspecialchars($user['full_name']) . '</td>
                <td>' . htmlspecialchars($user['email']) . '</td>
                <td><span class="item-status status-' . ($user['role'] === 'admin' ? 'resolved' : 'active') . '">' . ucfirst($user['role']) . '</span></td>
                <td>' . date('M j, Y', strtotime($user['created_at'])) . '</td>
                <td>';
        
        if ($user['id'] !== $_SESSION['user_id'] && $user['role'] !== 'admin') {
            echo '<form method="POST" style="display: inline;" onsubmit="return confirm(\'Are you sure you want to delete this user?\')">
                    <input type="hidden" name="user_id" value="' . $user['id'] . '">
                    <button type="submit" name="delete_user" class="btn btn-danger" style="padding: 0.3rem 0.8rem; font-size: 0.8rem;">Delete</button>
                  </form>';
        } else {
            echo '<span style="color: #666;">Cannot delete</span>';
        }
        
        echo '</td>
              </tr>';
    }
    
    echo '</tbody>
                </table>
            </div>
          </div>';
    
    // Items Management
    $query = "SELECT i.*, u.username, u.full_name 
              FROM items i 
              JOIN users u ON i.user_id = u.id 
              ORDER BY i.created_at DESC 
              LIMIT 50";
    $stmt = $db->prepare($query);
    $stmt->execute();
    $recent_items = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    echo '<div class="content-card">
            <h3>Recent Items Management</h3>
            <div style="overflow-x: auto;">
                <table class="table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Title</th>
                            <th>Type</th>
                            <th>Category</th>
                            <th>Status</th>
                            <th>User</th>
                            <th>Date</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>';
    
    foreach ($recent_items as $item) {
        echo '<tr>
                <td>' . $item['id'] . '</td>
                <td>' . htmlspecialchars(substr($item['title'], 0, 30)) . (strlen($item['title']) > 30 ? '...' : '') . '</td>
                <td><span class="item-status status-' . $item['type'] . '">' . ucfirst($item['type']) . '</span></td>
                <td>' . htmlspecialchars($item['category']) . '</td>
                <td><span class="item-status status-' . $item['status'] . '">' . ucfirst($item['status']) . '</span></td>
                <td>' . htmlspecialchars($item['username']) . '</td>
                <td>' . date('M j, Y', strtotime($item['created_at'])) . '</td>
                <td>
                    <a href="?page=item&id=' . $item['id'] . '" class="btn" style="padding: 0.3rem 0.8rem; font-size: 0.8rem; margin-right: 0.5rem;">View</a>
                    <form method="POST" style="display: inline;" onsubmit="return confirm(\'Are you sure you want to delete this item?\')">
                        <input type="hidden" name="item_id" value="' . $item['id'] . '">
                        <button type="submit" name="delete_item" class="btn btn-danger" style="padding: 0.3rem 0.8rem; font-size: 0.8rem;">Delete</button>
                    </form>
                </td>
              </tr>';
    }
    
    echo '</tbody>
                </table>
            </div>
          </div>';
}
            ?>
        </div>
    </main>

    <footer>
        <div class="container">
            <p>&copy; 2025 Lost & Found Management System. All rights reserved.</p>
        </div>
    </footer>
</body>
</html>
