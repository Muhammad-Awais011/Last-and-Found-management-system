<?php
require_once __DIR__ . '/../config.php';

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
