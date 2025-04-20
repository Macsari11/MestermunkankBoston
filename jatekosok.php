<?php
session_start();
$isLoggedIn = isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true;

if (!$isLoggedIn) {
    error_log("Nem vagyok bejelentkezve: " . print_r($_SESSION, true));
} else {
    error_log("Bejelentkezve, felhasználónév: " . $_SESSION['username']);
}

if (isset($_POST['logout'])) {
    session_destroy();
    header("Location: ../index.php");
    exit();
}

$servername = "localhost";
$username = "root"; 
$password = "";
$dbname = "user_db";

try {
    $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $conn->exec("SET NAMES utf8"); 

   
    $table_check = $conn->query("SHOW TABLES LIKE 'players'");
    if ($table_check->rowCount() == 0) {
        throw new PDOException("A 'players' tábla nem található az adatbázisban!");
    }

    
    $stmt_starting = $conn->prepare("SELECT * FROM players WHERE is_starting = 1 LIMIT 5");
    $stmt_starting->execute();
    $startingFive = $stmt_starting->fetchAll(PDO::FETCH_ASSOC);

    
    $stmt_bench = $conn->prepare("SELECT * FROM players WHERE is_starting = 0");
    $stmt_bench->execute();
    $benchPlayers = $stmt_bench->fetchAll(PDO::FETCH_ASSOC);

} catch (PDOException $e) {
    error_log("Adatbázis hiba: " . $e->getMessage());
    die("Adatbázis kapcsolat sikertelen! Hibaüzenet: " . htmlspecialchars($e->getMessage()));
}

?>

<!DOCTYPE html>
<html lang="hu">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Boston Celtics - Játékosok</title>
    <link rel="stylesheet" href="jatekos.css">
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&family=Bebas+Neue&display=swap" rel="stylesheet">
</head>
<body>
    <header class="hero-header">
        <nav class="nav-container">
            <div class="nav-links">
                <?php if ($isLoggedIn): ?>
                    <a href="../esemeny/esemenyek.php">Események</a>
                    <a href="jatekosok.php">Játékosok</a>
                    <a href="../kozosseg/kozosseg.php">Közösség</a>
                <?php else: ?>
                    <a href="#" class="locked">Események</a>
                    <a href="#" class="locked">Játékosok</a>
                    <a href="#" class="locked">Közösség</a>
                <?php endif; ?>
            </div>
            <div class="logo-container">
                <a href="../index.php">
                    <img src="../kepek/logo.png" alt="Boston Celtics Logó" class="logo">
                </a>
            </div>
            <div class="auth-links">
                <?php if ($isLoggedIn): ?>
                    <div class="dropdown">
                        <span class="dropbtn">Üdv, <?php echo htmlspecialchars($_SESSION['username']); ?>!</span>
                        <div class="dropdown-content">
                            <form method="POST">
                                <button type="submit" name="logout">Kijelentkezés</button>
                            </form>
                        </div>
                    </div>
                <?php else: ?>
                    <a href="../login_register/index2.php" class="login">Bejelentkezés</a>
                    <a href="../login_register/index2.php" class="register">Regisztráció</a>
                <?php endif; ?>
            </div>
        </nav>
        <div class="hero-content">
            <h1 class="hero-title">Celtics Játékosok</h1>
            <p class="hero-subtitle">Ismerd meg a csapat sztárjait!</p>
            <button class="hero-button" id="explore-button">Fedezd fel!</button>
        </div>
    </header>

    <section class="explore-section" id="explore-section">
        <h2 class="section-title">Mit kínál a Játékosok oldal?</h2>
        <div class="explore-content">
            <div class="explore-item">
                <h3>Kezdőcsapat és Cserék</h3>
                <p>Válts a Boston Celtics kezdőötöse és a cserejátékosok között, hogy megismerd a teljes csapatot!</p>
            </div>
            <div class="explore-item">
                <h3>Részletes Játékos Adatok</h3>
                <p>Kattints a "Tudj meg többet" gombra, hogy lásd a játékosok pozícióját, statisztikáit és egyéb adatait!</p>
            </div>
            <div class="explore-item">
                <h3>A Csapat Története</h3>
                <p>Olvass a Boston Celtics legendás múltjáról, amely 17 bajnoki címmel büszkélkedhet!</p>
            </div>
        </div>
    </section>

    <main>
        <section class="players-section">
            <h2 class="section-title">A Csapat</h2>
            <div class="players-grid">
                <div class="card" id="card1"></div>
                <div class="card" id="card2"></div>
                <div class="card" id="card3"></div>
                <div class="card" id="card4"></div>
                <div class="card" id="card5"></div>
                <div class="card" id="card6" style="display: none;"></div>
                <div class="card" id="card7" style="display: none;"></div>
                <div class="card" id="card8" style="display: none;"></div>
                <div class="card" id="card9" style="display: none;"></div>
                <div class="card" id="card10" style="display: none;"></div>
                <div class="card" id="card11" style="display: none;"></div>
                <div class="card" id="card12" style="display: none;"></div>
                <div class="card" id="card13" style="display: none;"></div>
            </div>
            <button class="toggle-button">Cserék</button>
        </section>
        <section class="team-history">
            <h2 class="section-title">A Csapat Története</h2>
            <p class="history-text">A Boston Celtics az NBA egyik legsikeresebb csapata, 17 bajnoki címmel büszkélkedhet. Az 1950-es években Bill Russell, majd később Larry Bird vezetésével váltak legendává. Ma is a liga élvonalában szerepelnek!</p>
        </section>
    </main>

    <footer class="futuristic-footer">
        <div class="footer-content">
            <div class="footer-logo">
                <img src="../kepek/logo.png" alt="Boston Celtics Logó" class="footer-logo-img">
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
            <p>© <span id="year"></span> Boston Celtics Rajongói Oldal | Minden jog fenntartva</p>
        </div>
    </footer>

    <script>
        const startingFive = <?php
            $json = json_encode($startingFive, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP);
            echo $json === false ? '[]' : $json;
        ?>;
        const benchPlayers = <?php
            $json = json_encode($benchPlayers, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP);
            echo $json === false ? '[]' : $json;
        ?>;
    </script>
    <script src="jatekos.js"></script>
</body>
</html>