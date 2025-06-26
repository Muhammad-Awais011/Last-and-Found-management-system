<?php
require_once __DIR__ . '/../config.php';

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
