<?php
// Adatbázis kapcsolat
$servername = "127.0.0.1";
$username = "root"; // Cseréld ki, ha szükséges
$password = "";     // Cseréld ki, ha szükséges
$dbname = "user_db";

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die("Kapcsolódási hiba: " . $conn->connect_error);
}

// Kérdések lekérdezése
$sql = "SELECT question, answers, correct_answer FROM quiz_questions";
$result = $conn->query($sql);

$questions = [];
if ($result->num_rows > 0) {
    while ($row = $result->fetch_assoc()) {
        $questions[] = [
            'question' => $row['question'],
            'answers' => json_decode($row['answers'], true),
            'correct' => $row['correct_answer']
        ];
    }
}

// JSON formátumban visszaadjuk az adatokat
header('Content-Type: application/json');
echo json_encode($questions);

$conn->close();
?>