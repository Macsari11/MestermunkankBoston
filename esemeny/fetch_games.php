<?php
header('Content-Type: application/json');

// Ellenőrizzük, hogy az év és hónap paraméterek meg vannak-e adva
if (!isset($_GET['year']) || !isset($_GET['month'])) {
    echo json_encode(['error' => 'Missing parameters: year and month required']);
    exit;
}

$year = intval($_GET['year']);
$month = intval($_GET['month']);

// Ellenőrizzük, hogy a hónap értéke 1 és 12 között van-e
if ($month < 1 || $month > 12) {
    echo json_encode(['error' => 'Invalid month value. Must be between 1 and 12.']);
    exit;
}

// Helyes dátumtartomány meghatározása
$startDate = sprintf("%04d-%02d-01", $year, $month);
$endDate = date("Y-m-t", strtotime($startDate)); // Hónap utolsó napja

$celticsTeamId = 2; // Boston Celtics team ID

// API URL összeállítása
$apiUrl = "https://www.balldontlie.io/api/v1/games?team_ids[]=$celticsTeamId&start_date=$startDate&end_date=$endDate&per_page=100";

// cURL inicializálása és beállítása
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $apiUrl);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

$games = []; // Üres tömb inicializálása

if ($httpCode === 200 && $response !== false) {
    // JSON válasz dekódolása
    $data = json_decode($response, true);
    
    // Ellenőrizzük, hogy van-e érvényes adat az API válaszban
    if ($data && isset($data['data']) && !empty($data['data'])) {
        $games = array_map(function ($game) use ($celticsTeamId) {
            $gameDate = new DateTime($game['date']);
            $opponent = ($game['home_team']['id'] === $celticsTeamId) ? 
                        $game['visitor_team']['name'] : 
                        $game['home_team']['name'];
            $time = ($game['status'] === "Final") ? "Final" : ($game['status'] ?: "TBD");

            return [
                'date' => $gameDate->format('Y-m-d'),
                'opponent' => $opponent,
                'time' => $time
            ];
        }, $data['data']);
    } else {
        error_log("No games found for the given month.");
    }
} else {
    error_log("API request failed with HTTP code: $httpCode");
}

// JSON válasz küldése
echo json_encode($games, JSON_PRETTY_PRINT);
?>
