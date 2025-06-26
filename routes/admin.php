<?php
require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../functions.php';

if (!isAdmin()) {
    header('Location: ?page=home');
    exit();
}

$database = new Database();
$db = $database->getConnection();

// Handle notification actions
if ($_POST) {
    if (isset($_POST['mark_read'])) {
        $notification_id = (int)$_POST['notification_id'];
        markNotificationAsRead($notification_id);
        echo '<div class="alert alert-success">Notification marked as read!</div>';
    }
    
    if (isset($_POST['mark_all_read'])) {
        markAllNotificationsAsRead();
        echo '<div class="alert alert-success">All notifications marked as read!</div>';
    }
    
    if (isset($_POST['delete_user'])) {
        $user_id = (int)$_POST['user_id'];
        if ($user_id !== $_SESSION['user_id']) {
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

// Get notification count
$unread_count = getUnreadNotificationCount();

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
            <div class="stat-card" style="background: #ff6b6b; color: white;">
                <div class="stat-number">' . $unread_count . '</div>
                <div class="stat-label">Unread Notifications</div>
            </div>
        </div>
      </div>';

// Notifications Section
$notifications = getNotifications(null, 20); // Get last 20 notifications

echo '<div class="content-card">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
            <h3>Recent Notifications</h3>
            <form method="POST" style="display: inline;">
                <button type="submit" name="mark_all_read" class="btn btn-secondary">Mark All as Read</button>
            </form>
        </div>';

if (empty($notifications)) {
    echo '<p>No notifications found.</p>';
} else {
    echo '<div style="max-height: 400px; overflow-y: auto;">
            <table class="table">
                <thead>
                    <tr>
                        <th>Date</th>
                        <th>Title</th>
                        <th>Message</th>
                        <th>Type</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>';
    
    foreach ($notifications as $notification) {
        $status_class = $notification['is_read'] ? 'status-resolved' : 'status-active';
        $status_text = $notification['is_read'] ? 'Read' : 'Unread';
        
        echo '<tr>
                <td>' . date('M j, Y g:i A', strtotime($notification['created_at'])) . '</td>
                <td>' . htmlspecialchars($notification['title']) . '</td>
                <td>' . htmlspecialchars(substr($notification['message'], 0, 50)) . (strlen($notification['message']) > 50 ? '...' : '') . '</td>
                <td><span class="item-status status-' . $notification['type'] . '">' . ucfirst(str_replace('_', ' ', $notification['type'])) . '</span></td>
                <td><span class="item-status ' . $status_class . '">' . $status_text . '</span></td>
                <td>';
        
        if (!$notification['is_read']) {
            echo '<form method="POST" style="display: inline; margin-right: 0.5rem;">
                    <input type="hidden" name="notification_id" value="' . $notification['id'] . '">
                    <button type="submit" name="mark_read" class="btn" style="padding: 0.3rem 0.8rem; font-size: 0.8rem;">Mark Read</button>
                  </form>';
        }
        
        if ($notification['related_item_id']) {
            echo '<a href="?page=item&id=' . $notification['related_item_id'] . '" class="btn" style="padding: 0.3rem 0.8rem; font-size: 0.8rem;">View Item</a>';
        }
        
        echo '</td>
              </tr>';
    }
    
    echo '</tbody>
            </table>
          </div>';
}

echo '</div>';

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