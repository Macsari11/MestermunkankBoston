<?php
session_start();
$isLoggedIn = isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true;

// Ha nem bejelentkezett, átirányítás
if (!$isLoggedIn) {
    header("Location: login_register/index2.php");
    exit();
}

// Adatbázis kapcsolat
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "user_db";

try {
    $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Adatbázis kapcsolat sikertelen: " . $e->getMessage());
}

// Felhasználó adatainak lekérése
$user_stmt = $conn->prepare("SELECT username, email, profile_pic FROM users WHERE username = :username");
$user_stmt->execute(['username' => $_SESSION['username']]);
$user = $user_stmt->fetch(PDO::FETCH_ASSOC);

// Jelszóváltoztatás kezelése
if (isset($_POST['change_password'])) {
    $current_password = $_POST['current_password'];
    $new_password = $_POST['new_password'];
    $confirm_password = $_POST['confirm_password'];

    $stmt = $conn->prepare("SELECT password FROM users WHERE username = :username");
    $stmt->execute(['username' => $_SESSION['username']]);
    $stored_password = $stmt->fetchColumn();

    if (password_verify($current_password, $stored_password)) {
        if ($new_password === $confirm_password) {
            $new_password_hashed = password_hash($new_password, PASSWORD_DEFAULT);
            $update_stmt = $conn->prepare("UPDATE users SET password = :password WHERE username = :username");
            $update_stmt->execute(['password' => $new_password_hashed, 'username' => $_SESSION['username']]);
            $password_message = "Jelszó sikeresen megváltoztatva!";
        } else {
            $password_message = "Az új jelszavak nem egyeznek!";
        }
    } else {
        $password_message = "A jelenlegi jelszó helytelen!";
    }
}

// Profilkép feltöltése
if (isset($_FILES['profile_pic']) && $_FILES['profile_pic']['error'] == 0) {
    $allowed_types = ['image/jpeg', 'image/png', 'image/gif'];
    $max_size = 5 * 1024 * 1024; // 5MB
    $upload_dir = "profile_pics/";
    
    if (!file_exists($upload_dir)) {
        mkdir($upload_dir, 0777, true);
    }

    $file_type = $_FILES['profile_pic']['type'];
    $file_size = $_FILES['profile_pic']['size'];
    $file_tmp = $_FILES['profile_pic']['tmp_name'];
    $file_name = $_SESSION['username'] . "_" . time() . "." . pathinfo($_FILES['profile_pic']['name'], PATHINFO_EXTENSION);

    if (in_array($file_type, $allowed_types) && $file_size <= $max_size) {
        $destination = $upload_dir . $file_name;
        if (move_uploaded_file($file_tmp, $destination)) {
            $update_stmt = $conn->prepare("UPDATE users SET profile_pic = :profile_pic WHERE username = :username");
            $update_stmt->execute(['profile_pic' => $destination, 'username' => $_SESSION['username']]);
            $user['profile_pic'] = $destination; // Frissítjük a változót
            $upload_message = "Profilkép sikeresen feltöltve!";
        } else {
            $upload_message = "Hiba a fájl feltöltésekor!";
        }
    } else {
        $upload_message = "Érvénytelen fájltípus vagy méret (max 5MB, JPG/PNG/GIF)!";
    }
}

// Kijelentkezés kezelése
if (isset($_POST['logout'])) {
    session_destroy();
    header("Location: index.php");
    exit();
}
?>

<!DOCTYPE html>
<html lang="hu">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Boston Celtics - Profil</title>
    <link rel="stylesheet" href="style.css">
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&family=Bebas+Neue&display=swap" rel="stylesheet">
</head>
<body>
    <header class="hero-header">
        <nav class="nav-container">
            <div class="nav-links">
                <a href="esemeny/esemenyek.php">Események</a>
                <a href="jatekosok.php">Játékosok</a>
                <a href="kozosseg/kozosseg.php">Közösség</a>
            </div>
            <div class="logo-container">
                <a href="index.php">
                    <img src="kepek/logo.png" alt="Boston Celtics Logó" class="logo">
                </a>
            </div>
            <div class="auth-links">
                <div class="dropdown">
                    <span class="dropbtn">Üdv, <?php echo htmlspecialchars($_SESSION['username']); ?>!</span>
                    <div class="dropdown-content">
                        <a href="profile.php">Profil</a>
                        <form method="POST">
                            <button type="submit" name="logout">Kijelentkezés</button>
                        </form>
                    </div>
                </div>
            </div>
        </nav>
        <div class="hero-content">
            <h1 class="hero-title">Profil</h1>
            <p class="hero-subtitle">Kezeld adataidat!</p>
        </div>
    </header>

    <main>
        <section class="profile-section">
            <h2 class="section-title">Profilod</h2>
            <div class="profile-container">
                <!-- Profilkép megjelenítése és feltöltése -->
                <div class="profile-pic">
                    <?php if ($user['profile_pic']): ?>
                        <img src="<?php echo htmlspecialchars($user['profile_pic']); ?>" alt="Profilkép" class="current-pic">
                    <?php else: ?>
                        <p>Nincs profilkép feltöltve.</p>
                    <?php endif; ?>
                    <form method="POST" enctype="multipart/form-data">
                        <input type="file" name="profile_pic" accept="image/*" required>
                        <button type="submit" class="hero-button">Feltöltés</button>
                    </form>
                    <?php if (isset($upload_message)): ?>
                        <p class="message"><?php echo $upload_message; ?></p>
                    <?php endif; ?>
                </div>

                <!-- Felhasználói adatok -->
                <div class="profile-info">
                    <p><strong>Felhasználónév:</strong> <?php echo htmlspecialchars($user['username']); ?></p>
                    <p><strong>Email:</strong> <?php echo htmlspecialchars($user['email']); ?></p>
                </div>

                <!-- Jelszóváltoztatás -->
                <div class="password-change">
                    <h3>Jelszó megváltoztatása</h3>
                    <form method="POST">
                        <input type="password" name="current_password" placeholder="Jelenlegi jelszó" required>
                        <input type="password" name="new_password" placeholder="Új jelszó" required>
                        <input type="password" name="confirm_password" placeholder="Új jelszó újra" required>
                        <button type="submit" name="change_password" class="hero-button">Jelszó változtatása</button>
                    </form>
                    <?php if (isset($password_message)): ?>
                        <p class="message"><?php echo $password_message; ?></p>
                    <?php endif; ?>
                </div>
            </div>
        </section>
    </main>

    <footer class="futuristic-footer">
        <div class="footer-content">
            <div class="footer-logo">
                <img src="kepek/logo.png" alt="Boston Celtics Logo" class="footer-logo-img">
            </div>
            <div class="footer-links">
                <a href="footer/adatvedelem.html">Adatvédelmi Nyilatkozat</a>
                <a href="footer/felhasznalasi_feltetelek.html">Felhasználási Feltételek</a>
                <a href="footer/kapcsolat.html">Kapcsolat</a>
            </div>
            <div class="social-media">
                <a href="https://facebook.com/bostonceltics" target="_blank"><img src="kepek/facebook.png" alt="Facebook" class="social-icon"></a>
                <a href="https://twitter.com/celtics" target="_blank"><img src="kepek/x.svg" alt="Twitter" class="social-icon"></a>
                <a href="https://instagram.com/bostonceltics" target="_blank"><img src="kepek/instagram.webp" alt="Instagram" class="social-icon"></a>
            </div>
        </div>
        <div class="footer-bottom">
            <p>© <span id="year"></span> Boston Celtics Fan Page | Minden jog fenntartva</p>
        </div>
    </footer>
    <script src="script.js"></script>
    <script>
        document.getElementById('year').textContent = new Date().getFullYear();
    </script>
</body>
</html>