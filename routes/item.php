<?php
require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../functions.php';

$item_id = $_GET['id'] ?? 0;
if (!$item_id) {
    echo '<div class="content-card"><div class="alert alert-error">Invalid item ID.</div></div>';
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
    echo '<div class="content-card"><div class="alert alert-error">Item not found.</div></div>';
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
    echo '<div style="width: 100%; height: 250px; background: #f8f9fa; border-radius: 8px; display: flex; align-items: center; justify-content: center; margin-bottom: 1rem; color: #666;">📷 No Image Available</div>';
}
echo '</div><div>';
echo '<h2>' . htmlspecialchars($item['title']) . '</h2>';
echo '<p><strong>Type:</strong> <span class="item-status status-' . $item['type'] . '">' . ucfirst($item['type']) . '</span></p>';
echo '<p><strong>Category:</strong> ' . htmlspecialchars($item['category']) . '</p>';
echo '<p><strong>Status:</strong> <span class="item-status status-' . $item['status'] . '">' . ucfirst($item['status']) . '</span></p>';
echo '<p><strong>Location:</strong> ' . htmlspecialchars($item['location']) . '</p>';
echo '<p><strong>Date:</strong> ' . date('F j, Y', strtotime($item['date_lost_found'])) . '</p>';
echo '<p><strong>Reported:</strong> ' . date('F j, Y g:i A', strtotime($item['created_at'])) . '</p>';
echo '<h3>Description</h3>';
echo '<p>' . nl2br(htmlspecialchars($item['description'])) . '</p>';
echo '<h3>Contact Information</h3>';
echo '<p><strong>Reported by:</strong> ' . htmlspecialchars($item['full_name']) . '</p>';
if (!empty($item['contact_info'])) {
    echo '<p><strong>Contact:</strong> ' . htmlspecialchars($item['contact_info']) . '</p>';
} else {
    echo '<p><strong>Contact:</strong> Contact through system</p>';
}
if (isLoggedIn()) {
    echo '<p><strong>Email:</strong> ' . htmlspecialchars($item['email']) . '</p>';
    if (!empty($item['phone'])) {
        echo '<p><strong>Phone:</strong> ' . htmlspecialchars($item['phone']) . '</p>';
    }
}
echo '</div></div>';
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
echo '<div style="margin-top: 2rem;"><a href="?page=browse" class="btn btn-secondary">← Back to Browse</a></div>';
