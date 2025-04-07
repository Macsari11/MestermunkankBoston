<?php
session_start();
$isLoggedIn = isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true;

// Adatbázis kapcsolat PDO-val
$servername = "localhost";
$port = "3306"; // Alapértelmezett MySQL port, ha eltér, módosítsd
$username = "root";
$password = "";
$dbname = "user_db";

try {
    $dsn = "mysql:host=$servername;port=$port;dbname=$dbname;charset=utf8";
    $conn = new PDO($dsn, $username, $password);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $conn->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    error_log("Adatbázis kapcsolat sikeres!");
} catch (PDOException $e) {
    error_log("Adatbázis hiba: " . $e->getMessage());
    die("Adatbázis kapcsolat sikertelen: " . $e->getMessage());
}

// Ha nem bejelentkezett, átirányítás
if (!$isLoggedIn) {
    header("Location: ../login_register/index2.php");
    exit();
}

// Felhasználó ID lekérése
$user_stmt = $conn->prepare("SELECT id FROM users WHERE username = :username");
$user_stmt->execute(['username' => $_SESSION['username']]);
$user = $user_stmt->fetch();
$user_id = $user['id'];

// Új üzenet küldése
if (isset($_POST['message']) && !empty($_POST['message']) && isset($_POST['room_id'])) {
    $room_id = $_POST['room_id'];
    $message = $_POST['message'];
    $stmt = $conn->prepare("INSERT INTO messages (room_id, user_id, message) VALUES (:room_id, :user_id, :message)");
    $stmt->execute(['room_id' => $room_id, 'user_id' => $user_id, 'message' => $message]);
}
?>

<!DOCTYPE html>
<html lang="hu">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Boston Celtics - Csevegés</title>
    <link rel="stylesheet" href="../style.css">
    <link rel="stylesheet" href="chat.css">
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&family=Bebas+Neue&display=swap" rel="stylesheet">
</head>
<body>
    <header class="hero-header">
        <nav class="nav-container">
            <div class="nav-links">
                <a href="../esemeny/esemenyek.php">Események</a>
                <a href="../jatekosok.php">Játékosok</a>
                <a href="kozosseg.php">Közösség</a>
            </div>
            <div class="logo-container">
                <a href="../index.php">
                    <img src="../kepek/logo.png" alt="Boston Celtics Logó" class="logo">
                </a>
            </div>
            <div class="auth-links">
                <div class="dropdown">
                    <span class="dropbtn">Üdv, <?php echo htmlspecialchars($_SESSION['username']); ?>!</span>
                    <div class="dropdown-content">
                        <form method="POST" action="../index.php">
                            <button type="submit" name="logout">Kijelentkezés</button>
                        </form>
                    </div>
                </div>
            </div>
        </nav>
        <div class="hero-content">
            <h1 class="hero-title">Csevegés</h1>
            <p class="hero-subtitle">Csatlakozz a Celtics rajongókhoz!</p>
        </div>
    </header>

    <main>
        <section class="chat-section">
            <?php if (!isset($_GET['room_id'])): ?>
                <h2 class="section-title">Válassz egy csevegőszobát</h2>
                <div class="room-list">
                    <?php
                    $rooms_stmt = $conn->query("SELECT * FROM rooms");
                    while ($room = $rooms_stmt->fetch()) {
                        echo "<a href='chat.php?room_id={$room['id']}' class='room-card'>{$room['name']}<br><small>{$room['description']}</small></a>";
                    }
                    ?>
                </div>
            <?php else: ?>
                <?php
                $room_id = $_GET['room_id'];
                $room_stmt = $conn->prepare("SELECT * FROM rooms WHERE id = :id");
                $room_stmt->execute(['id' => $room_id]);
                $room = $room_stmt->fetch();
                ?>
                <h2 class="section-title"><?php echo htmlspecialchars($room['name']); ?></h2>
                <p><?php echo htmlspecialchars($room['description']); ?></p>
                <div class="chat-container">
                    <div class="messages">
                        <?php
                        $messages_stmt = $conn->prepare("
                            SELECT m.message, m.created_at, u.username 
                            FROM messages m 
                            JOIN users u ON m.user_id = u.id 
                            WHERE m.room_id = :room_id 
                            ORDER BY m.created_at ASC
                        ");
                        $messages_stmt->execute(['room_id' => $room_id]);
                        while ($msg = $messages_stmt->fetch()) {
                            echo "<div class='message'>";
                            echo "<span class='username'>" . htmlspecialchars($msg['username']) . "</span>: ";
                            echo "<span class='message-content'>" . htmlspecialchars($msg['message']) . "</span> - ";
                            echo "<span class='timestamp'>" . $msg['created_at'] . "</span>";
                            echo "</div>";
                        }
                        ?>
                    </div>
                    <form method="POST" action="">
                        <input type="hidden" name="room_id" value="<?php echo $room_id; ?>">
                        <textarea name="message" placeholder="Írd be az üzeneted..." required></textarea>
                        <button type="submit" class="hero-button">Küldés</button>
                    </form>
                </div>
            <?php endif; ?>
        </section>
    </main>

    <footer class="futuristic-footer">
        <div class="footer-content">
            <div class="footer-logo">
                <img src="../kepek/logo.png" alt="Boston Celtics Logo" class="footer-logo-img">
            </div>
            <div class="footer-links">
                <a href="../footer/adatvedelem.html">Adatvédelmi Nyilatkozat</a>
                <a href="../footer/felhasznalasi_feltetelek.html">Felhasználási Feltételek</a>
                <a href="../footer/kapcsolat.html">Kapcsolat</a>
            </div>
            <div class="social-media">
                <a href="https://facebook.com/bostonceltics" target="_blank"><img src="../kepek/facebook.png" alt="Facebook" class="social-icon"></a>
                <a href="https://twitter.com/celtics" target="_blank"><img src="../kepek/x.svg" alt="Twitter" class="social-icon"></a>
                <a href="https://instagram.com/bostonceltics" target="_blank"><img src="../kepek/instagram.webp" alt="Instagram" class="social-icon"></a>
            </div>
        </div>
        <div class="footer-bottom">
            <p>© <span id="year"></span> Boston Celtics Fan Page | Minden jog fenntartva</p>
        </div>
    </footer>
    <script src="../script.js"></script>
    <script>
        document.getElementById('year').textContent = new Date().getFullYear();
    </script>
</body>
</html>