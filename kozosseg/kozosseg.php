<?php
session_start();
$isLoggedIn = isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true;

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
    <title>Boston Celtics - Közösség</title>
    <link rel="stylesheet" href="../style.css">
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&family=Bebas+Neue&display=swap" rel="stylesheet">
</head>
<body>
    <header class="hero-header">
        <nav class="nav-container">
            <div class="nav-links">
                <?php if ($isLoggedIn): ?>
                    <a href="../esemeny/esemenyek.php">Események</a>
                    <a href="../jatekosok.php">Játékosok</a>
                    <a href="kozosseg.php">Közösség</a>
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
            <h1 class="hero-title">Közösség</h1>
            <p class="hero-subtitle">Csatlakozz a Celtics rajongókhoz!</p>
            <?php if ($isLoggedIn): ?>
                <a href="chat.php" class="hero-button">Csevegés indítása</a>
            <?php endif; ?>
        </div>
    </header>

    <main>
        <section class="explore-section">
            <h2 class="section-title">Mit kínál a Közösség?</h2>
            <div class="explore-content">
                <div class="explore-item">
                    <h3>Csevegés</h3>
                    <p>Csatlakozz a csevegőszobákhoz, és beszélgess más rajongókkal valós időben!</p>
                </div>
                <div class="explore-item">
                    <h3>Rajongói közösség</h3>
                    <p>Oszd meg élményeidet és támogassuk együtt a csapatot!</p>
                </div>
            </div>
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