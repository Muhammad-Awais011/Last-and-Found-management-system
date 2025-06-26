<?php
require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../functions.php';

redirectIfNotLoggedIn();

$error = '';
$success = '';

if ($_POST) {
    $title = sanitizeInput($_POST['title']);
    $description = sanitizeInput($_POST['description']);
    $category = sanitizeInput($_POST['category']);
    $type = sanitizeInput($_POST['type']);
    $location = sanitizeInput($_POST['location']);
    $date_lost_found = sanitizeInput($_POST['date_lost_found']);
    $contact_info = sanitizeInput($_POST['contact_info']);
    
    if (empty($title) || empty($description) || empty($category) || empty($type) || empty($location) || empty($date_lost_found)) {
        $error = 'Please fill in all required fields.';
    } else {
        $database = new Database();
        $db = $database->getConnection();
        
        $image_path = null;
        if (isset($_FILES['image']) && $_FILES['image']['error'] === UPLOAD_ERR_OK) {
            $image_path = handleImageUpload($_FILES['image']);
        }
        
        $query = "INSERT INTO items (user_id, title, description, category, type, location, date_lost_found, contact_info, image_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
        $stmt = $db->prepare($query);
        
        if ($stmt->execute([$_SESSION['user_id'], $title, $description, $category, $type, $location, $date_lost_found, $contact_info, $image_path])) {
            $item_id = $db->lastInsertId();
            
            // Create notification for admins
            notifyAdminsOfNewItem($item_id, $title, $type, $_SESSION['full_name']);
            
            $success = 'Item reported successfully!';
            $_POST = array();
        } else {
            $error = 'Error reporting item. Please try again.';
        }
    }
}

echo '<div class="content-card">
        <h2>Report Lost/Found Item</h2>';

if ($error) {
    echo '<div class="alert alert-error">' . $error . '</div>';
}

if ($success) {
    echo '<div class="alert alert-success">' . $success . '</div>';
}

echo '<form method="POST" enctype="multipart/form-data">
        <div class="form-group">
            <label>Title: *</label>
            <input type="text" name="title" required value="' . ($_POST['title'] ?? '') . '">
        </div>
        
        <div class="form-group">
            <label>Type: *</label>
            <select name="type" required>
                <option value="">Select Type</option>
                <option value="lost"' . (($_POST['type'] ?? '') === 'lost' ? ' selected' : '') . '>Lost Item</option>
                <option value="found"' . (($_POST['type'] ?? '') === 'found' ? ' selected' : '') . '>Found Item</option>
            </select>
        </div>
        
        <div class="form-group">
            <label>Category: *</label>
            <select name="category" required>
                <option value="">Select Category</option>
                <option value="Electronics"' . (($_POST['category'] ?? '') === 'Electronics' ? ' selected' : '') . '>Electronics</option>
                <option value="Clothing"' . (($_POST['category'] ?? '') === 'Clothing' ? ' selected' : '') . '>Clothing</option>
                <option value="Accessories"' . (($_POST['category'] ?? '') === 'Accessories' ? ' selected' : '') . '>Accessories</option>
                <option value="Documents"' . (($_POST['category'] ?? '') === 'Documents' ? ' selected' : '') . '>Documents</option>
                <option value="Keys"' . (($_POST['category'] ?? '') === 'Keys' ? ' selected' : '') . '>Keys</option>
                <option value="Bags"' . (($_POST['category'] ?? '') === 'Bags' ? ' selected' : '') . '>Bags</option>
                <option value="Sports Equipment"' . (($_POST['category'] ?? '') === 'Sports Equipment' ? ' selected' : '') . '>Sports Equipment</option>
                <option value="Books"' . (($_POST['category'] ?? '') === 'Books' ? ' selected' : '') . '>Books</option>
                <option value="Jewelry"' . (($_POST['category'] ?? '') === 'Jewelry' ? ' selected' : '') . '>Jewelry</option>
                <option value="Other"' . (($_POST['category'] ?? '') === 'Other' ? ' selected' : '') . '>Other</option>
            </select>
        </div>
        
        <div class="form-group">
            <label>Description: *</label>
            <textarea name="description" rows="4" required placeholder="Provide detailed description including color, brand, distinctive features, etc.">' . ($_POST['description'] ?? '') . '</textarea>
        </div>
        
        <div class="form-group">
            <label>Location: *</label>
            <input type="text" name="location" required placeholder="Where was it lost/found?" value="' . ($_POST['location'] ?? '') . '">
        </div>
        
        <div class="form-group">
            <label>Date Lost/Found: *</label>
            <input type="date" name="date_lost_found" required value="' . ($_POST['date_lost_found'] ?? '') . '">
        </div>
        
        <div class="form-group">
            <label>Contact Information:</label>
            <input type="text" name="contact_info" placeholder="Phone number or email (optional)" value="' . ($_POST['contact_info'] ?? '') . '">
        </div>
        
        <div class="form-group">
            <label>Upload Image:</label>
            <input type="file" name="image" accept="image/*">
            <small style="color: #666;">Supported formats: JPG, PNG, GIF (optional)</small>
        </div>
        
        <button type="submit" class="btn">Report Item</button>
        <a href="?page=dashboard" class="btn btn-secondary">Cancel</a>
      </form>
      </div>';