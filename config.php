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
