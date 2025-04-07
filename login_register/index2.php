<?php
session_start();
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Adatbázis kapcsolat
$conn = new mysqli("localhost", "root", "", "user_db");
if ($conn->connect_error) {
    die("Kapcsolódási hiba: " . $conn->connect_error);
}

// Email ellenőrző függvény
function isValidEmail($email) {
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return false;
    }
    $pattern = '/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,63}$/';
    return preg_match($pattern, $email) === 1;
}

// Regisztráció befejezése (kvíz után)
if (isset($_POST['complete_registration'])) {
    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $password = password_hash($_POST['password'], PASSWORD_DEFAULT);

    if (!isValidEmail($email)) {
        echo "<script>alert('Érvénytelen email formátum!'); showForm('register-form');</script>";
    } else {
        $stmt = $conn->prepare("SELECT email FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            echo "<script>alert('Ez az email cím már regisztrálva van!'); showForm('login-form');</script>";
            $stmt->close();
        } else {
            $stmt->close();
            $stmt = $conn->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
            $stmt->bind_param("sss", $username, $email, $password);

            if ($stmt->execute()) {
                echo "<script>alert('Sikeres regisztráció! Jelentkezz be!'); showForm('login-form');</script>";
                session_unset();
            } else {
                echo "<script>alert('Hiba történt a regisztráció során: " . $conn->error . "'); showForm('register-form');</script>";
            }
            $stmt->close();
            header("Location: index2.php");
            exit();
        }
    }
}

// Bejelentkezés kezelése
if (isset($_POST['login'])) {
    $username = trim($_POST['username']);
    $password = $_POST['password'];

    // Először ellenőrizzük, hogy létezik-e a felhasználó és helyes-e a jelszó
    $stmt = $conn->prepare("SELECT password, role, is_banned FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $stmt->bind_result($hashed_password, $role, $is_banned);
    
    // Ha nem találjuk a felhasználót, vagy a jelszó hibás
    if (!$stmt->fetch() || !password_verify($password, $hashed_password)) {
        echo "<script>alert('Hibás felhasználónév vagy jelszó!'); showForm('login-form');</script>";
    } else {
        // Ha a felhasználó létezik és a jelszó helyes, ellenőrizzük a kitiltási állapotot
        if ($is_banned == 1) {
            echo "<script>alert('Ez a felhasználó ki van tiltva!'); showForm('login-form');</script>";
        } else {
            // Ha minden rendben, bejelentkeztetjük
            $_SESSION['logged_in'] = true;
            $_SESSION['username'] = $username;
            $_SESSION['role'] = $role;

            // Admin ellenőrzés és átirányítás
            if ($role === 'admin') {
                header("Location: ../admin/admin_dashboard.php");
            } else {
                header("Location: ../index.php");
            }
            exit();
        }
    }
    $stmt->close();
}

// Regisztráció indítása (kvízre irányít)
if (isset($_POST['register'])) {
    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $password = $_POST['password'];

    if (!isValidEmail($email)) {
        echo "<script>alert('Érvénytelen email formátum!'); showForm('register-form');</script>";
    } else {
        $stmt = $conn->prepare("SELECT email FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            echo "<script>alert('Ez az email cím már regisztrálva van!'); showForm('login-form');</script>";
            $stmt->close();
        } else {
            $stmt->close();
            $_SESSION['temp_registration'] = [
                'username' => $username,
                'email' => $email,
                'password' => $password
            ];
            header("Location: ../kviz/index.php");
            exit();
        }
    }
}

$conn->close();
?>

<!DOCTYPE html>
<html lang="hu">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bejelentkezés / Regisztráció</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <div class="form-box" id="login-form">
            <h2>Bejelentkezés</h2>
            <form method="POST">
                <input type="text" name="username" placeholder="Felhasználónév" required>
                <input type="password" name="password" placeholder="Jelszó" required>
                <button type="submit" name="login">Bejelentkezés</button>
            </form>
            <p>Nincs fiókod? <a href="#" onclick="showForm('register-form')">Regisztrálj itt!</a></p>
        </div>

        <div class="form-box" id="register-form">
            <h2>Regisztráció</h2>
            <form method="POST">
                <input type="text" name="username" placeholder="Felhasználónév" required>
                <input type="email" name="email" placeholder="E-mail" required>
                <input type="password" name="password" placeholder="Jelszó" required>
                <button type="submit" name="register">Regisztráció</button>
            </form>
            <p>Van már fiókod? <a href="#" onclick="showForm('login-form')">Jelentkezz be itt!</a></p>
        </div>
    </div>

    <script src="script.js"></script>
    <script>
        document.addEventListener("DOMContentLoaded", function() {
            showForm('login-form');
        });
    </script>
</body>
</html>