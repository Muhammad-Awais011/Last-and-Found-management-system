<?php
require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../functions.php';

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
