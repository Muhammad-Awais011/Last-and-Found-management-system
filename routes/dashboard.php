<?php
require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../functions.php';

redirectIfNotLoggedIn();
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
