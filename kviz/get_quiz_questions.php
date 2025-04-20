<?php
$servername = "127.0.0.1";
$username = "root"; 
$password = "";     
$dbname = "user_db";

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die("Kapcsolódási hiba: " . $conn->connect_error);
}

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

header('Content-Type: application/json');
echo json_encode($questions);

$conn->close();
?>