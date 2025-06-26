<?php
session_start();
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/functions.php';
// Auto-setup database on first run
if (!isset($_SESSION['db_setup'])) {
    setupDatabase();
    $_SESSION['db_setup'] = true;
}
$page = $_GET['page'] ?? 'home';
// HTML header
?><!DOCTYPE html>
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
            $route_file = __DIR__ . '/routes/' . basename($page) . '.php';
            if (file_exists($route_file)) {
                include $route_file;
            } else {
                echo '<div class="content-card"><div class="alert alert-error">Page not found.</div></div>';
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
