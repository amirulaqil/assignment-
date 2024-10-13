<?php
session_start();
include 'config.php'; // Include the database connection

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Get form input values
    $username = $_POST['username'];
    $password = $_POST['password'];

    // Prepare SQL query to retrieve user info
    $stmt = $conn->prepare("SELECT id, password FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $stmt->store_result();
    $stmt->bind_result($id, $hashed_password);
    $stmt->fetch();

    // Verify user credentials
    if ($stmt->num_rows > 0 && password_verify($password, $hashed_password)) {
        // Start session and redirect on success
        $_SESSION['user_id'] = $id;
        header("Location: home.php");
        exit();
    } else {
        // Show error message on invalid login
        $error = "Invalid credentials. Please try again.";
    }

    // Close statement and connection
    $stmt->close();
    $conn->close();
}
?>

<?php include 'header.php'; ?>

<h2>Login</h2>

<?php if (isset($error)): ?>
    <div class="alert alert-danger" role="alert">
        <?= $error ?>
    </div>
<?php endif; ?>

<form method="POST">
    <div class="form-group">
        <label for="username">Username</label>
        <input type="text" class="form-control" id="username" name="username" required>
    </div>
    <div class="form-group">
        <label for="password">Password</label>
        <input type="password" class="form-control" id="password" name="password" required>
    </div>
    <button type="submit" class="btn btn-primary mt-3">Login</button>
</form>

<?php include 'footer.php'; ?>