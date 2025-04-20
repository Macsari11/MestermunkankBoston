<?php
session_start();

if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true || $_SESSION['role'] !== 'admin') {
    header("Location: ../login_register/index2.php");
    exit();
}

$conn = new mysqli("localhost", "root", "", "user_db");
if ($conn->connect_error) {
    die("Kapcsolódási hiba: " . $conn->connect_error);
}

$users_query = "SELECT id, username, email, role, is_banned FROM users";
$users_result = $conn->query($users_query);

$messages_query = "SELECT m.id, m.room_id, m.user_id, m.message, m.created_at, u.username, r.name as room_name 
                 FROM messages m 
                 JOIN users u ON m.user_id = u.id 
                 JOIN rooms r ON m.room_id = r.id";
$messages_result = $conn->query($messages_query);

$players_query = "SELECT id, name, age, height, position, img, stats, is_starting FROM players";
$players_result = $conn->query($players_query);

$rooms_query = "SELECT id, name, description FROM rooms";
$rooms_result = $conn->query($rooms_query);

if (isset($_POST['add_room'])) {
    $room_name = trim($_POST['room_name']);
    $room_description = trim($_POST['room_description']);

    if (!empty($room_name)) {
        $stmt = $conn->prepare("INSERT INTO rooms (name, description) VALUES (?, ?)");
        $stmt->bind_param("ss", $room_name, $room_description);
        if ($stmt->execute()) {
            $stmt->close();
            header("Location: admin_dashboard.php#rooms");
            exit();
        } else {
            echo "Hiba a szoba létrehozása során: " . $conn->error;
        }
    } else {
        echo "A szoba neve nem lehet üres!";
    }
}

if (isset($_POST['toggle_ban'])) {
    $user_id = $_POST['user_id'];
    $is_banned = $_POST['is_banned'] == 1 ? 0 : 1;
    $stmt = $conn->prepare("UPDATE users SET is_banned = ? WHERE id = ?");
    $stmt->bind_param("ii", $is_banned, $user_id);
    if ($stmt->execute()) {
        $stmt->close();
        header("Location: admin_dashboard.php");
        exit();
    } else {
        echo "Hiba a kitiltás során: " . $conn->error;
    }
}

if (isset($_POST['delete_message'])) {
    $message_id = $_POST['message_id'];
    $stmt = $conn->prepare("DELETE FROM messages WHERE id = ?");
    $stmt->bind_param("i", $message_id);
    if ($stmt->execute()) {
        $stmt->close();
        header("Location: admin_dashboard.php");
        exit();
    } else {
        echo "Hiba az üzenet törlése során: " . $conn->error;
    }
}

if (isset($_POST['delete_player'])) {
    $player_id = $_POST['player_id'];
    $stmt = $conn->prepare("DELETE FROM players WHERE id = ?");
    $stmt->bind_param("i", $player_id);
    if ($stmt->execute()) {
        $stmt->close();
        header("Location: admin_dashboard.php#players");
        exit();
    } else {
        echo "Hiba a játékos törlése során: " . $conn->error;
    }
}

if (isset($_POST['add_player'])) {
    $name = trim($_POST['name']);
    $age = (int)$_POST['age'];
    $height = trim($_POST['height']);
    $position = trim($_POST['position']);
    $img = trim($_POST['img']);
    $stats = trim($_POST['stats']);
    $is_starting = isset($_POST['is_starting']) ? 1 : 0;

    $stmt = $conn->prepare("INSERT INTO players (name, age, height, position, img, stats, is_starting) VALUES (?, ?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("sissssi", $name, $age, $height, $position, $img, $stats, $is_starting);
    if ($stmt->execute()) {
        $stmt->close();
        header("Location: admin_dashboard.php#players");
        exit();
    } else {
        echo "Hiba a játékos hozzáadása során: " . $conn->error;
    }
}

if (isset($_POST['edit_player'])) {
    $player_id = $_POST['player_id'];
    $name = trim($_POST['name']);
    $age = (int)$_POST['age'];
    $height = trim($_POST['height']);
    $position = trim($_POST['position']);
    $img = trim($_POST['img']);
    $stats = trim($_POST['stats']);
    $is_starting = isset($_POST['is_starting']) ? 1 : 0;

    $stmt = $conn->prepare("UPDATE players SET name = ?, age = ?, height = ?, position = ?, img = ?, stats = ?, is_starting = ? WHERE id = ?");
    $stmt->bind_param("sissssii", $name, $age, $height, $position, $img, $stats, $is_starting, $player_id);
    if ($stmt->execute()) {
        $stmt->close();
        header("Location: admin_dashboard.php#players");
        exit();
    } else {
        echo "Hiba a játékos szerkesztése során: " . $conn->error;
    }
}
?>

<!DOCTYPE html>
<html lang="hu">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Felület</title>
    <link rel="stylesheet" href="admin_style.css">
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&family=Bebas+Neue&display=swap" rel="stylesheet">
</head>
<body>
    <header class="admin-header">
        <h1>Üdvözöllek az Admin Felületen, <?php echo htmlspecialchars($_SESSION['username']); ?>!</h1>
        <nav class="admin-nav">
            <a href="#users">Felhasználók kezelése</a>
            <a href="#messages">Üzenetek kezelése</a>
            <a href="#players">Játékosok kezelése</a>
            <a href="#rooms">Szobák kezelése</a>
            <form method="POST" style="display:inline;">
                <button type="submit" name="logout">Kijelentkezés</button>
            </form>
        </nav>
    </header>

    <main class="admin-main">
        <section class="admin-section" id="users">
            <h2>Felhasználók</h2>
            <table class="admin-table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Felhasználónév</th>
                        <th>Email</th>
                        <th>Szerepkör</th>
                        <th>Állapot</th>
                        <th>Műveletek</th>
                    </tr>
                </thead>
                <tbody>
                    <?php while ($user = $users_result->fetch_assoc()): ?>
                        <tr>
                            <td><?php echo $user['id']; ?></td>
                            <td><?php echo htmlspecialchars($user['username']); ?></td>
                            <td><?php echo htmlspecialchars($user['email']); ?></td>
                            <td><?php echo $user['role'] ? htmlspecialchars($user['role']) : 'Felhasználó'; ?></td>
                            <td><?php echo $user['is_banned'] ? 'Kitiltva' : 'Aktív'; ?></td>
                            <td>
                                <form method="POST" style="display:inline;">
                                    <input type="hidden" name="user_id" value="<?php echo $user['id']; ?>">
                                    <input type="hidden" name="is_banned" value="<?php echo $user['is_banned']; ?>">
                                    <button type="submit" name="toggle_ban" class="action-btn <?php echo $user['is_banned'] ? 'unban' : 'ban'; ?>">
                                        <?php echo $user['is_banned'] ? 'Kitiltás feloldása' : 'Kitiltás'; ?>
                                    </button>
                                </form>
                            </td>
                        </tr>
                    <?php endwhile; ?>
                </tbody>
            </table>
        </section>

        <section class="admin-section" id="messages">
            <h2>Üzenetek</h2>
            <table class="admin-table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Szoba</th>
                        <th>Felhasználó</th>
                        <th>Üzenet</th>
                        <th>Küldés ideje</th>
                        <th>Műveletek</th>
                    </tr>
                </thead>
                <tbody>
                    <?php while ($message = $messages_result->fetch_assoc()): ?>
                        <tr>
                            <td><?php echo $message['id']; ?></td>
                            <td><?php echo htmlspecialchars($message['room_name']); ?></td>
                            <td><?php echo htmlspecialchars($message['username']); ?></td>
                            <td><?php echo htmlspecialchars($message['message']); ?></td>
                            <td><?php echo $message['created_at']; ?></td>
                            <td>
                                <form method="POST" style="display:inline;">
                                    <input type="hidden" name="message_id" value="<?php echo $message['id']; ?>">
                                    <button type="submit" name="delete_message" class="action-btn delete">Törlés</button>
                                </form>
                            </td>
                        </tr>
                    <?php endwhile; ?>
                </tbody>
            </table>
        </section>

        <section class="admin-section" id="players">
            <h2>Játékosok</h2>

            <div class="admin-form">
                <h3>Új játékos hozzáadása</h3>
                <form method="POST">
                    <input type="text" name="name" placeholder="Név" required>
                    <input type="number" name="age" placeholder="Kor" required>
                    <input type="text" name="height" placeholder="Magasság (pl. 6'8\")" required>
                    <input type="text" name="position" placeholder="Pozíció (pl. SF)" required>
                    <input type="text" name="img" placeholder="Kép elérési útja (pl. /Pics/JT.jpg)" required>
                    <input type="text" name="stats" placeholder="Statisztikák (pl. PPG: 26.9, RPG: 8.1, APG: 4.9)" required>
                    <label>
                        <input type="checkbox" name="is_starting"> Kezdő játékos
                    </label>
                    <button type="submit" name="add_player" class="action-btn">Hozzáadás</button>
                </form>
            </div>

            <table class="admin-table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Név</th>
                        <th>Kor</th>
                        <th>Magasság</th>
                        <th>Pozíció</th>
                        <th>Kép</th>
                        <th>Statisztikák</th>
                        <th>Kezdő</th>
                        <th>Műveletek</th>
                    </tr>
                </thead>
                <tbody>
                    <?php while ($player = $players_result->fetch_assoc()): ?>
                        <tr>
                            <td><?php echo $player['id']; ?></td>
                            <td><?php echo htmlspecialchars($player['name']); ?></td>
                            <td><?php echo $player['age']; ?></td>
                            <td><?php echo htmlspecialchars($player['height']); ?></td>
                            <td><?php echo htmlspecialchars($player['position']); ?></td>
                            <td><?php echo htmlspecialchars($player['img']); ?></td>
                            <td><?php echo htmlspecialchars($player['stats']); ?></td>
                            <td><?php echo $player['is_starting'] ? 'Igen' : 'Nem'; ?></td>
                            <td>
                                <button class="action-btn edit" onclick="showEditForm(<?php echo $player['id']; ?>, '<?php echo htmlspecialchars($player['name']); ?>', <?php echo $player['age']; ?>, '<?php echo htmlspecialchars($player['height']); ?>', '<?php echo htmlspecialchars($player['position']); ?>', '<?php echo htmlspecialchars($player['img']); ?>', '<?php echo htmlspecialchars($player['stats']); ?>', <?php echo $player['is_starting']; ?>)">Szerkesztés</button>
                                <form method="POST" style="display:inline;">
                                    <input type="hidden" name="player_id" value="<?php echo $player['id']; ?>">
                                    <button type="submit" name="delete_player" class="action-btn delete">Törlés</button>
                                </form>
                            </td>
                        </tr>
                    <?php endwhile; ?>
                </tbody>
            </table>

            <div class="admin-form" id="edit-player-form" style="display:none;">
                <h3>Játékos szerkesztése</h3>
                <form method="POST">
                    <input type="hidden" name="player_id" id="edit-player-id">
                    <input type="text" name="name" id="edit-player-name" placeholder="Név" required>
                    <input type="number" name="age" id="edit-player-age" placeholder="Kor" required>
                    <input type="text" name="height" id="edit-player-height" placeholder="Magasság (pl. 6'8\")" required>
                    <input type="text" name="position" id="edit-player-position" placeholder="Pozíció (pl. SF)" required>
                    <input type="text" name="img" id="edit-player-img" placeholder="Kép elérési útja (pl. /Pics/JT.jpg)" required>
                    <input type="text" name="stats" id="edit-player-stats" placeholder="Statisztikák (pl. PPG: 26.9, RPG: 8.1, APG: 4.9)" required>
                    <label>
                        <input type="checkbox" name="is_starting" id="edit-player-is-starting"> Kezdő játékos
                    </label>
                    <button type="submit" name="edit_player" class="action-btn">Mentés</button>
                    <button type="button" class="action-btn cancel" onclick="hideEditForm()">Mégse</button>
                </form>
            </div>
        </section>

        <section class="admin-section" id="rooms">
            <h2>Szobák</h2>

            <div class="admin-form">
                <h3>Új szoba létrehozása</h3>
                <form method="POST">
                    <input type="text" name="room_name" placeholder="Szoba neve" required>
                    <textarea name="room_description" placeholder="Leírás (opcionális)" rows="3"></textarea>
                    <button type="submit" name="add_room" class="action-btn">Hozzáadás</button>
                </form>
            </div>

            <table class="admin-table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Név</th>
                        <th>Leírás</th>
                    </tr>
                </thead>
                <tbody>
                    <?php while ($room = $rooms_result->fetch_assoc()): ?>
                        <tr>
                            <td><?php echo $room['id']; ?></td>
                            <td><?php echo htmlspecialchars($room['name']); ?></td>
                            <td><?php echo htmlspecialchars($room['description'] ?? 'Nincs leírás'); ?></td>
                        </tr>
                    <?php endwhile; ?>
                </tbody>
            </table>
        </section>
    </main>

    <script>
        function showEditForm(id, name, age, height, position, img, stats, is_starting) {
            document.getElementById('edit-player-form').style.display = 'block';
            document.getElementById('edit-player-id').value = id;
            document.getElementById('edit-player-name').value = name;
            document.getElementById('edit-player-age').value = age;
            document.getElementById('edit-player-height').value = height;
            document.getElementById('edit-player-position').value = position;
            document.getElementById('edit-player-img').value = img;
            document.getElementById('edit-player-stats').value = stats;
            document.getElementById('edit-player-is-starting').checked = is_starting == 1;
        }

        function hideEditForm() {
            document.getElementById('edit-player-form').style.display = 'none';
        }
    </script>

    <?php
    if (isset($_POST['logout'])) {
        session_destroy();
        header("Location: ../login_register/index2.php");
        exit();
    }

    $conn->close();
    ?>
</body>
</html>