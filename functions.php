<?php
// functions.php - Helper functions

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

// Notification functions
function createNotification($title, $message, $type = 'item_reported', $related_item_id = null, $user_id = null) {
    $database = new Database();
    $db = $database->getConnection();
    
    $query = "INSERT INTO notifications (user_id, title, message, type, related_item_id) VALUES (?, ?, ?, ?, ?)";
    $stmt = $db->prepare($query);
    return $stmt->execute([$user_id, $title, $message, $type, $related_item_id]);
}

function getUnreadNotificationCount($user_id = null) {
    $database = new Database();
    $db = $database->getConnection();
    
    if ($user_id) {
        $query = "SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = FALSE";
        $stmt = $db->prepare($query);
        $stmt->execute([$user_id]);
    } else {
        // For admin, get all unread notifications
        $query = "SELECT COUNT(*) FROM notifications WHERE is_read = FALSE";
        $stmt = $db->prepare($query);
        $stmt->execute();
    }
    
    return $stmt->fetchColumn();
}

function getNotifications($user_id = null, $limit = 10) {
    $database = new Database();
    $db = $database->getConnection();
    
    // Sanitize limit to prevent SQL injection
    $limit = (int)$limit;
    if ($limit <= 0) $limit = 10;
    if ($limit > 100) $limit = 100; // Prevent excessive queries
    
    if ($user_id) {
        $query = "SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT $limit";
        $stmt = $db->prepare($query);
        $stmt->execute([$user_id]);
    } else {
        // For admin, get all notifications
        $query = "SELECT * FROM notifications ORDER BY created_at DESC LIMIT $limit";
        $stmt = $db->prepare($query);
        $stmt->execute();
    }
    
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

function markNotificationAsRead($notification_id) {
    $database = new Database();
    $db = $database->getConnection();
    
    $query = "UPDATE notifications SET is_read = TRUE WHERE id = ?";
    $stmt = $db->prepare($query);
    return $stmt->execute([$notification_id]);
}

function markAllNotificationsAsRead($user_id = null) {
    $database = new Database();
    $db = $database->getConnection();
    
    if ($user_id) {
        $query = "UPDATE notifications SET is_read = TRUE WHERE user_id = ?";
        $stmt = $db->prepare($query);
        $stmt->execute([$user_id]);
    } else {
        // For admin, mark all as read
        $query = "UPDATE notifications SET is_read = TRUE";
        $stmt = $db->prepare($query);
        $stmt->execute();
    }
}

function notifyAdminsOfNewItem($item_id, $item_title, $item_type, $reporter_name) {
    $title = "New " . ucfirst($item_type) . " Item Reported";
    $message = "User '$reporter_name' has reported a new $item_type item: '$item_title'. Please review it in the admin panel.";
    
    // Create notification for all admin users
    $database = new Database();
    $db = $database->getConnection();
    
    $query = "SELECT id FROM users WHERE role = 'admin'";
    $stmt = $db->prepare($query);
    $stmt->execute();
    $admins = $stmt->fetchAll(PDO::FETCH_COLUMN);
    
    foreach ($admins as $admin_id) {
        createNotification($title, $message, 'item_reported', $item_id, $admin_id);
    }
}