<?php
require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../functions.php';

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
