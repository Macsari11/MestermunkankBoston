<?php
header('Content-Type: application/json');

if (!isset($_GET['year']) || !isset($_GET['month'])) {
    echo json_encode(['error' => 'Missing parameters: year and month required']);
    exit;
}

$year = intval($_GET['year']);
$month = intval($_GET['month']);

if ($month < 1 || $month > 12) {
    echo json_encode(['error' => 'Invalid month value. Must be between 1 and 12.']);
    exit;
}

$startDate = sprintf("%04d-%02d-01", $year, $month);
$endDate = date("Y-m-t", strtotime($startDate));

$celticsTeamId = 2;

$apiUrl = "https://www.balldontlie.io/api/v1/games?team_ids[]=$celticsTeamId&start_date=$startDate&end_date=$endDate&per_page=100";

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $apiUrl);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

$games = [];

if ($httpCode === 200 && $response !== false) {
    $data = json_decode($response, true);
    
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

echo json_encode($games, JSON_PRETTY_PRINT);
?>
