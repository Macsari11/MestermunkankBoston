<?php
session_start();
?>

<!DOCTYPE html>
<html lang="hu">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Boston Celtics Kvíz</title>
    <link href="https://fonts.googleapis.com/css2?family=Exo+2:wght@400;700&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Exo 2', sans-serif;
            color: #FFFFFF;
            max-width: 1000px;
            margin: 0 auto;
            padding: 40px;
            min-height: 100vh;
            background: #008000; /* Egyszínű zöld háttér a képed alapján */
        }

        h1 {
            text-align: center;
            color: #FFFFFF;
            text-shadow: 0 0 20px #007A33, 0 0 40px #FFFFFF;
            font-size: 3em;
            margin-bottom: 50px;
            letter-spacing: 2px;
            text-transform: uppercase;
        }

        #quiz-container {
            background: rgba(0, 0, 0, 0.7);
            padding: 30px;
            border-radius: 0;
            border: 2px solid #007A33;
            box-shadow: 0 0 30px rgba(0, 122, 51, 0.5);
            backdrop-filter: blur(10px);
        }

        .question {
            margin-bottom: 25px;
            padding: 20px;
            background: rgba(255, 255, 255, 0.05);
            border-left: 4px solid #007A33;
            transition: all 0.3s ease;
        }

        .question:hover {
            background: rgba(255, 255, 255, 0.1);
            box-shadow: 0 0 20px rgba(255, 255, 255, 0.3);
        }

        input[type="radio"] {
            accent-color: #007A33;
            margin-right: 15px;
            transform: scale(1.2);
        }

        label {
            font-size: 1.2em;
            color: #FFFFFF;
            text-shadow: 0 0 5px rgba(0, 122, 51, 0.8);
            transition: color 0.3s ease;
        }

        label:hover {
            color: #FFFFFF;
            text-shadow: 0 0 10px rgba(255, 255, 255, 0.8);
        }

        button {
            display: block;
            margin: 40px auto;
            padding: 15px 50px;
            background: transparent;
            color: #FFFFFF;
            border: 2px solid #007A33;
            border-radius: 0;
            font-size: 1.3em;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.3s ease;
            text-transform: uppercase;
            letter-spacing: 2px;
            box-shadow: 0 0 20px rgba(0, 122, 51, 0.5);
        }

        button:hover {
            background: #007A33;
            color: #FFFFFF;
            box-shadow: 0 0 40px rgba(0, 122, 51, 0.9);
            border-color: #FFFFFF;
        }

        #result {
            text-align: center;
            margin-top: 40px;
            font-size: 1.5em;
            text-shadow: 0 0 15px #007A33;
            letter-spacing: 1px;
        }

        #timer {
            text-align: center;
            font-size: 1.5em;
            margin-bottom: 20px;
            color: #FFFFFF;
            text-shadow: 0 0 10px #007A33;
        }
    </style>
</head>
<body>
    <h1>Boston Celtics Kvíz</h1>
    <div id="timer">Hátralévő idő: 3:00</div>
    <div id="quiz-container"></div>
    <button onclick="checkAnswers()">Kész</button>
    <div id="result"></div>

    <script>
        let questions = [];
        let displayedQuestions = [];

        async function fetchQuestions() {
            try {
                console.log("Kérdések lekérdezése...");
                const response = await fetch('get_quiz_questions.php'); // Helyes elérési út
                if (!response.ok) {
                    throw new Error(`HTTP hiba! Státusz: ${response.status}`);
                }
                const data = await response.json();
                console.log("Lekérdezett adatok:", data);
                if (data.length === 0) {
                    console.warn("Nincsenek kérdések az adatbázisban!");
                    document.getElementById('quiz-container').innerHTML = "<p>Nincsenek kérdések az adatbázisban!</p>";
                    return;
                }
                questions = data;
                displayedQuestions = getRandomQuestions();
                loadQuiz();
            } catch (error) {
                console.error('Hiba a kérdések lekérdezésekor:', error);
                document.getElementById('quiz-container').innerHTML = "<p>Hiba történt a kérdések betöltésekor! Ellenőrizd a konzolt.</p>";
            }
        }

        function getRandomQuestions() {
            const shuffled = [...questions].sort(() => 0.5 - Math.random());
            return shuffled.slice(0, 10);
        }

        function loadQuiz() {
            const quizContainer = document.getElementById('quiz-container');
            if (displayedQuestions.length === 0) {
                quizContainer.innerHTML = "<p>Nincsenek megjeleníthető kérdések!</p>";
                return;
            }
            displayedQuestions.forEach((q, index) => {
                const div = document.createElement('div');
                div.className = 'question';
                div.innerHTML = `
                    <p>${index + 1}. ${q.question}</p>
                    ${q.answers.map((answer, i) => `
                        <input type="radio" name="q${index}" value="${answer}" id="q${index}a${i}">
                        <label for="q${index}a${i}">${answer}</label><br>
                    `).join('')}
                `;
                quizContainer.appendChild(div);
            });
        }

        function checkAnswers() {
            let correctCount = 0;
            displayedQuestions.forEach((q, index) => {
                const selected = document.querySelector(`input[name="q${index}"]:checked`);
                if (selected && selected.value === q.correct) {
                    correctCount++;
                }
            });

            const resultDiv = document.getElementById('result');
            if (correctCount >= 7) {
                resultDiv.style.color = '#007A33';
                resultDiv.textContent = `Megcsináltad! ${correctCount}/10 - Gratulálunk!`;

                fetch('../login_register/index2.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: new URLSearchParams({
                        'complete_registration': '1',
                        'username': '<?php echo isset($_SESSION["temp_registration"]["username"]) ? $_SESSION["temp_registration"]["username"] : ""; ?>',
                        'email': '<?php echo isset($_SESSION["temp_registration"]["email"]) ? $_SESSION["temp_registration"]["email"] : ""; ?>',
                        'password': '<?php echo isset($_SESSION["temp_registration"]["password"]) ? $_SESSION["temp_registration"]["password"] : ""; ?>'
                    }).toString()
                })
                .then(response => response.text())
                .then(() => {
                    resultDiv.textContent = 'Sikeres regisztráció!';
                    setTimeout(() => {
                        window.location.href = '../login_register/index2.php';
                    }, 2000);
                })
                .catch(error => {
                    console.error('Hiba:', error);
                    resultDiv.textContent = 'Hiba történt a regisztráció során!';
                });
            } else {
                resultDiv.style.color = '#FFFFFF';
                resultDiv.textContent = `Nem sikerült!: ${correctCount}/10 - Ha csatlakozni akarsz, próbáld újra!`;
            }

            document.querySelectorAll('input[type="radio"]').forEach(input => input.disabled = true);
            document.querySelector('button').disabled = true;
            clearInterval(timerInterval);
        }

        let timeLeft = 180;
        const timerDisplay = document.getElementById('timer');

        function updateTimer() {
            const minutes = Math.floor(timeLeft / 60);
            const seconds = timeLeft % 60;
            timerDisplay.textContent = `Hátralévő idő: ${minutes}:${seconds < 10 ? '0' + seconds : seconds}`;

            if (timeLeft <= 0) {
                clearInterval(timerInterval);
                timerDisplay.textContent = "Lejárt az idő!";
                checkAnswers();
            } else {
                timeLeft--;
            }
        }

        const timerInterval = setInterval(updateTimer, 1000);

        fetchQuestions();
    </script>
</body>
</html>