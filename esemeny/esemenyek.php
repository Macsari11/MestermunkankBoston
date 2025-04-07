<?php
session_start();
$isLoggedIn = isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true;

// Hibakereső üzenet (éles környezetben törölhető)
if (!$isLoggedIn) {
    error_log("Nem vagyok bejelentkezve: " . print_r($_SESSION, true));
} else {
    error_log("Bejelentkezve, felhasználónév: " . $_SESSION['username']);
}

// Kijelentkezés kezelése
if (isset($_POST['logout'])) {
    session_destroy();
    header("Location: ../index.php");
    exit();
}
?>

<!DOCTYPE html>
<html lang="hu">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Boston Celtics - Események</title>
    <link rel="stylesheet" href="esemeny.css">
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&family=Bebas+Neue&display=swap" rel="stylesheet">
</head>
<body>
    <header class="hero-header">
        <nav class="nav-container">
            <div class="nav-links">
                <?php if ($isLoggedIn): ?>
                    <a href="esemenyek.php">Események</a>
                    <a href="../jatekosok.php">Játékosok</a>
                    <a href="../kozosseg/kozosseg.php">Közösség</a>
                <?php else: ?>
                    <a href="#" class="locked">Események</a>
                    <a href="#" class="locked">Játékosok</a>
                    <a href="#" class="locked">Közösség</a>
                <?php endif; ?>
            </div>
            <div class="logo-container">
                <a href="../index.php">
                    <img src="../Pics/logo-removebg-preview.png" alt="Boston Celtics Logó" class="logo">
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
                    <a href="admin_user/index.html" class="login">Bejelentkezés</a>
                    <a href="admin_user/index.html" class="register">Regisztráció</a>
                <?php endif; ?>
            </div>
        </nav>
        <div class="hero-content">
            <h1 class="hero-title">CELTICS ESEMÉNYEK</h1>
            <p class="hero-subtitle">Nézd meg a közelgő mérkőzéseket!</p>
            <button class="hero-button">Fedezd fel a naptárat!</button>
        </div>
    </header>

    <main>
        <section class="calendar-section">
            <h2 class="section-title">Mérkőzés Naptár</h2>
            <div id="calendar-container">
                <div class="calendar-message">
                    <p>Készülj fel a Celtics legnagyobb meccseire!</p>
                    <a href="https://tippmixpro.hu" target="_blank" class="tippmix-button">Fogadni szeretnél?</a>
                </div>
                <div class="calendar-header">
                    <button id="prevMonth">❮</button>
                    <span id="currentMonthYear"></span>
                    <button id="nextMonth">❯</button>
                </div>
                <table id="calendar">
                    <thead>
                        <tr>
                            <th>H</th><th>K</th><th>Sz</th><th>Cs</th><th>P</th><th>Sz</th><th>V</th>
                        </tr>
                    </thead>
                    <tbody></tbody>
                </table>
            </div>
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
                <a href="https://twitter.com/celtics" target="_blank"><img src="../kepek/X.svg" alt="Twitter" class="social-icon"></a>
                <a href="https://instagram.com/bostonceltics" target="_blank"><img src="../kepek/instagram.webp" alt="Instagram" class="social-icon"></a>
            </div>
        </div>
        <div class="footer-bottom">
            <p>© <span id="year"></span> Boston Celtics Rajongói Oldal | Minden jog fenntartva</p>
        </div>
    </footer>

    <script src="esemeny.js"></script>
</body>
</html>