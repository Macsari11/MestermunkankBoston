<?php
session_start();
$isLoggedIn = isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true;

if ($isLoggedIn && $_SESSION['role'] === 'admin') {
    header("Location: admin/admin_dashboard.php");
    exit();
}

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
    <title>Boston Celtics - Üdvözlő oldal</title>
    <link rel="stylesheet" href="style.css">
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&family=Bebas+Neue&display=swap" rel="stylesheet">
</head>
<body>
    <div class="background-container"></div>

    <header class="hero-header">
        <nav class="nav-container">
            <div class="nav-links">
                <?php if ($isLoggedIn): ?>
                    <a href="esemeny/esemenyek.php">Események</a>
                    <a href="jatekosok.php">Játékosok</a>
                    <a href="kozosseg/kozosseg.php">Közösség</a>
                <?php else: ?>
                    <a href="#" class="locked">Események</a>
                    <a href="#" class="locked">Játékosok</a>
                    <a href="#" class="locked">Közösség</a>
                <?php endif; ?>
            </div>
            <div class="logo-container">
                <a href="index.php">
                    <img src="kepek/logo.png" alt="Boston Celtics Logó" class="logo">
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
                    <a href="login_register/index2.php" class="login">Bejelentkezés</a>
                    <a href="login_register/index2.php" class="register">Regisztráció</a>
                <?php endif; ?>
            </div>
        </nav>
        <div class="hero-content">
            <div class="welcome-banner">Welcome to the Celtics!</div>
            <h1 class="hero-title">Boston Celtics</h1>
            <p class="hero-subtitle">'Different here'</p>
            <button class="hero-button" id="explore-button">Fedezd fel!</button>
        </div>
    </header>

    <main>
        <section class="explore-section" id="explore-section">
            <h2 class="section-title">Mi vár rád, ha regisztrálsz?</h2>
            <div class="explore-content">
                <div class="explore-item">
                    <h3>Események</h3>
                    <p>Fedezd fel a Boston Celtics közelgő mérkőzéseit, böngéssz a részletes időpontok és további információk között!</p>
                </div>
                <div class="explore-item">
                    <h3>Játékosok</h3>
                    <p>Ismerd meg a csapat sztárjait, böngéssz a részletes statisztikák és játékosprofilok között!</p>
                </div>
                <div class="explore-item">
                    <h3>Közösség</h3>
                    <p>Csatlakozz a Celtics rajongókhoz, vegyél részt izgalmas beszélgetésekben!</p>
                </div>
            </div>
        </section>

        <section class="carousel-section" id="carousel-section">
            <div class="carousel">
                <video src="kepek/2025---boston-celtics-intro-video-2024.mp4" autoplay loop muted class="carousel-slide active">
                    <source src="kepek/2025---boston-celtics-intro-video-2024.mp4" type="video/mp4">
                </video>
            </div>
        </section>

        <section class="info-section">
            <h2 class="section-title">Celtics Highlights</h2>
            <div class="info-grid">
                <a href="https://hu.wikipedia.org/wiki/Boston_Celtics#" class="info-card">18 bajnoki cím 🏆</a>
                <a href="https://www.sport1tv.hu/sztori/108836/bill-russell-egy-legenda-volt-a-palyan-es-a-palyan-kivul-egyarant/" class="info-card">Bill Russell 🏀</a>
                <a href="https://24.hu/sport/2017/07/31/a-nagy-harmas-amely-orokre-megvaltoztatta-a-kosarlabdat/" class="info-card">Nagy Hármas 🎯</a>
                <a href="https://en.wikipedia.org/wiki/Jays_(Boston_Celtics)" class="info-card">Jayson & Jaylen ⭐</a>
            </div>
        </section>
    </main>

    <footer class="futuristic-footer">
        <div class="footer-content">
            <div class="footer-logo">
                <img src="kepek/logo.png" alt="Boston Celtics Logo" class="footer-logo-img">
            </div>
            <div class="footer-links">
                <a href="/footer/adatvedelem.html">Adatvédelmi Nyilatkozat</a>
                <a href="/footer/felhasznalasi_feltetelek.html">Felhasználási Feltételek</a>
                <a href="/footer/kapcsolat.html">Kapcsolat</a>
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
</body>
</html>