-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Gép: 127.0.0.1
-- Létrehozás ideje: 2025. Ápr 03. 12:05
-- Kiszolgáló verziója: 10.4.28-MariaDB
-- PHP verzió: 8.2.4

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Adatbázis: `user_db`
--
CREATE DATABASE IF NOT EXISTS `user_db` DEFAULT CHARACTER SET utf8 COLLATE utf8_hungarian_ci;
USE `user_db`;

-- --------------------------------------------------------

--
-- Tábla szerkezet ehhez a táblához `messages`
--

CREATE TABLE `messages` (
  `id` int(11) NOT NULL,
  `room_id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `message` text NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_hungarian_ci;

--
-- A tábla adatainak kiíratása `messages`
--

INSERT INTO `messages` (`id`, `room_id`, `user_id`, `message`, `created_at`) VALUES
(6, 1, 4, 'komoly volt', '2025-04-01 09:25:14'),
(7, 1, 4, 'szerintem is\r\n', '2025-04-01 09:25:21'),
(8, 1, 4, 'ilyen meccset meg nem lattam', '2025-04-01 09:25:29'),
(9, 1, 4, 'fiam', '2025-04-03 08:59:08'),
(10, 1, 5, 'srgr', '2025-04-03 09:28:19'),
(11, 2, 4, 'bazdmeg\r\n', '2025-04-03 09:46:43');

-- --------------------------------------------------------

--
-- Tábla szerkezet ehhez a táblához `players`
--

CREATE TABLE `players` (
  `id` int(11) NOT NULL,
  `name` varchar(100) NOT NULL,
  `age` int(11) NOT NULL,
  `height` varchar(10) NOT NULL,
  `position` varchar(50) NOT NULL,
  `img` varchar(255) NOT NULL,
  `stats` text DEFAULT NULL,
  `is_starting` tinyint(1) DEFAULT 0,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_hungarian_ci;

--
-- A tábla adatainak kiíratása `players`
--

INSERT INTO `players` (`id`, `name`, `age`, `height`, `position`, `img`, `stats`, `is_starting`, `created_at`) VALUES
(79, 'Jayson Tatum', 27, '6\'8\"', 'SF', '/Pics/JT.jpg', 'PPG: 26.9, RPG: 8.1, APG: 4.9', 1, '2025-03-24 12:44:06'),
(80, 'Jaylen Brown', 28, '6\'6\"', 'SG', '/Pics/JB.jpg', 'PPG: 23.0, RPG: 5.5, APG: 3.6', 1, '2025-03-24 12:44:06'),
(81, 'Kristaps Porzingis', 29, '7\'3\"', 'C', '/Pics/KP.jpg', 'PPG: 20.1, RPG: 7.2, BPG: 1.9', 1, '2025-03-24 12:44:06'),
(82, 'Derrick White', 30, '6\'4\"', 'PG', '/Pics/DW.jpg', 'PPG: 15.2, RPG: 4.2, APG: 5.1', 1, '2025-03-24 12:44:06'),
(83, 'Jrue Holiday', 34, '6\'4\"', 'PG', '/Pics/JH.jpg', 'PPG: 12.5, RPG: 5.4, APG: 4.8', 1, '2025-03-24 12:44:06'),
(84, 'Al Horford', 38, '6\'9\"', 'C', '/Pics/AH.jpg', 'PPG: 8.6, RPG: 6.2, APG: 2.6', 0, '2025-03-24 12:44:06'),
(85, 'Payton Pritchard', 27, '6\'1\"', 'PG', '/Pics/PP.jpg', 'PPG: 9.6, RPG: 3.2, APG: 3.4', 0, '2025-03-24 12:44:06'),
(86, 'Sam Hauser', 27, '6\'7\"', 'SF', '/Pics/SH.jpg', 'PPG: 8.9, RPG: 3.5, APG: 1.0', 0, '2025-03-24 12:44:06'),
(87, 'Luke Kornet', 29, '7\'2\"', 'C', '/Pics/LK.jpg', 'PPG: 5.3, RPG: 4.1, BPG: 1.1', 0, '2025-03-24 12:44:06'),
(88, 'Neemias Queta', 25, '7\'0\"', 'C', '/Pics/NQ.jpg', 'PPG: 4.6, RPG: 4.4, BPG: 0.8', 0, '2025-03-24 12:44:06'),
(89, 'Baylor Scheierman', 24, '6\'6\"', 'SG', '/Pics/BS.jpg', 'PPG: 3.1, RPG: 1.2, APG: 0.5', 0, '2025-03-24 12:44:06'),
(90, 'Jaden Springer', 22, '6\'4\"', 'SG', '/Pics/JS.jpg', 'PPG: 2.1, RPG: 1.0, APG: 0.8', 0, '2025-03-24 12:44:06'),
(91, 'Xavier Tillman', 26, '6\'8\"', 'PF', '/Pics/XT.jpg', 'PPG: 4.0, RPG: 2.7, APG: 1.0', 0, '2025-03-24 12:44:06');

-- --------------------------------------------------------

--
-- Tábla szerkezet ehhez a táblához `quiz_questions`
--

CREATE TABLE `quiz_questions` (
  `id` int(11) NOT NULL,
  `question` varchar(255) NOT NULL,
  `answers` varchar(255) NOT NULL,
  `correct_answer` varchar(100) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_hungarian_ci;

--
-- A tábla adatainak kiíratása `quiz_questions`
--

INSERT INTO `quiz_questions` (`id`, `question`, `answers`, `correct_answer`) VALUES
(1, 'Mikor alapították a Boston Celtics-et?', '[\"1946\", \"1950\", \"1960\", \"1936\"]', '1946'),
(2, 'Hány bajnokságot nyert a Celtics?', '[\"15\", \"17\", \"19\", \"13\"]', '17'),
(3, 'Ki a Celtics legendás center játékosa?', '[\"Larry Bird\", \"Bill Russell\", \"Paul Pierce\", \"Kevin Garnett\"]', 'Bill Russell'),
(4, 'Melyik színek a Celtics hivatalos színei?', '[\"Zöld-Fehér\", \"Kék-Piros\", \"Fekete-Sárga\", \"Zöld-Kék\"]', 'Zöld-Fehér'),
(5, 'Hol játszik hazai mérkőzéseit a Celtics?', '[\"Madison Square Garden\", \"TD Garden\", \"Staples Center\", \"Barclays Center\"]', 'TD Garden'),
(6, 'Mikor alapították a Boston Celtics-et?', '[\"1946\", \"1950\", \"1960\", \"1936\"]', '1946'),
(7, 'Hány bajnokságot nyert a Celtics?', '[\"15\", \"17\", \"19\", \"13\"]', '17'),
(8, 'Ki a Celtics legendás center játékosa?', '[\"Larry Bird\", \"Bill Russell\", \"Paul Pierce\", \"Kevin Garnett\"]', 'Bill Russell'),
(9, 'Melyik színek a Celtics hivatalos színei?', '[\"Zöld-Fehér\", \"Kék-Piros\", \"Fekete-Sárga\", \"Zöld-Kék\"]', 'Zöld-Fehér'),
(10, 'Hol játszik hazai mérkőzéseit a Celtics?', '[\"Madison Square Garden\", \"TD Garden\", \"Staples Center\", \"Barclays Center\"]', 'TD Garden'),
(11, 'Ki volt a Celtics edzője a 2008-as bajnoki cím idején?', '[\"Doc Rivers\", \"Brad Stevens\", \"Red Auerbach\", \"Rick Pitino\"]', 'Doc Rivers'),
(12, 'Melyik évben draftolták Jayson Tatumot?', '[\"2015\", \"2016\", \"2017\", \"2018\"]', '2017'),
(13, 'Ki nyerte a legtöbb bajnoki gyűrűt a Celtics játékosaként?', '[\"Bill Russell\", \"Larry Bird\", \"John Havlicek\", \"Bob Cousy\"]', 'Bill Russell'),
(14, 'Hány bajnoki címet nyert Bill Russell?', '[\"9\", \"11\", \"13\", \"7\"]', '11'),
(15, 'Melyik csapat a Celtics legnagyobb riválisa?', '[\"Lakers\", \"Knicks\", \"76ers\", \"Bulls\"]', 'Lakers'),
(16, 'Ki volt a Celtics első afroamerikai játékosa?', '[\"Chuck Cooper\", \"Bill Russell\", \"Sam Jones\", \"K.C. Jones\"]', 'Chuck Cooper'),
(17, 'Melyik évben nyerte az első bajnoki címét a Celtics?', '[\"1955\", \"1957\", \"1960\", \"1948\"]', '1957'),
(18, 'Ki volt a Celtics legendás edzője az 1950-60-as években?', '[\"Red Auerbach\", \"Phil Jackson\", \"Pat Riley\", \"Gregg Popovich\"]', 'Red Auerbach'),
(19, 'Hány All-Star szereplése volt Larry Birdnek?', '[\"10\", \"12\", \"14\", \"8\"]', '12'),
(20, 'Melyik évben vonult vissza Larry Bird?', '[\"1990\", \"1992\", \"1994\", \"1988\"]', '1992'),
(21, 'Ki nyerte a 2008-as döntő MVP-je?', '[\"Paul Pierce\", \"Kevin Garnett\", \"Ray Allen\", \"Rajon Rondo\"]', 'Paul Pierce'),
(22, 'Melyik játékos beceneve \'The Truth\'?', '[\"Paul Pierce\", \"Kevin Garnett\", \"Larry Bird\", \"Jayson Tatum\"]', 'Paul Pierce'),
(23, 'Hány szezonban volt a Celtics az NBA része?', '[\"75\", \"77\", \"79\", \"73\"]', '77'),
(24, 'Ki draftolta Jaylen Brownt?', '[\"Celtics\", \"Nets\", \"76ers\", \"Lakers\"]', 'Celtics'),
(25, 'Melyik évben draftolták Kevin Garnettet?', '[\"1993\", \"1995\", \"1997\", \"1999\"]', '1995'),
(26, 'Hány triplát dobott Ray Allen a Celtics színeiben?', '[\"798\", \"650\", \"921\", \"543\"]', '798'),
(27, 'Ki volt a Celtics első női segédedzője?', '[\"Kara Lawson\", \"Becky Hammon\", \"Nancy Lieberman\", \"Lisa Boyer\"]', 'Kara Lawson'),
(28, 'Melyik évben lett Brad Stevens a Celtics edzője?', '[\"2011\", \"2013\", \"2015\", \"2017\"]', '2013'),
(29, 'Hány meccset nyert sorozatban a Celtics 2008-2009-ben?', '[\"19\", \"17\", \"15\", \"21\"]', '19'),
(30, 'Ki a Celtics kabalafigurája?', '[\"Lucky\", \"Benny\", \"Sly\", \"Hugo\"]', 'Lucky'),
(31, 'Melyik évben nyerte meg utoljára a Celtics a bajnokságot (2023-ig)?', '[\"2008\", \"2010\", \"2006\", \"2012\"]', '2008'),
(32, 'Hány pontot szerzett Jayson Tatum a 2022-es rájátszásban?', '[\"614\", \"553\", \"487\", \"692\"]', '614'),
(33, 'Ki volt a Celtics elnöke 2021-től?', '[\"Brad Stevens\", \"Danny Ainge\", \"Red Auerbach\", \"Rick Pitino\"]', 'Brad Stevens'),
(34, 'Melyik évben lett Bob Cousy az év újonca?', '[\"1950\", \"1951\", \"1952\", \"1949\"]', '1951'),
(35, 'Hány All-NBA csapattagsága van Larry Birdnek?', '[\"9\", \"10\", \"11\", \"8\"]', '10'),
(36, 'Ki dobta a híres \'buzzer-beater\'-t 1987-ben a Lakers ellen?', '[\"Larry Bird\", \"Dennis Johnson\", \"Kevin McHale\", \"Robert Parish\"]', 'Larry Bird'),
(37, 'Melyik játékos nyert 8 bajnoki címet a Celtics-szel?', '[\"John Havlicek\", \"Tom Heinsohn\", \"Sam Jones\", \"K.C. Jones\"]', 'John Havlicek'),
(38, 'Hány évig volt Red Auerbach a Celtics edzője?', '[\"16\", \"14\", \"18\", \"12\"]', '16'),
(39, 'Melyik évben draftolták Rajon Rondót?', '[\"2004\", \"2005\", \"2006\", \"2007\"]', '2006'),
(40, 'Ki volt a Celtics első overall pickje 1950-ben?', '[\"Chuck Cooper\", \"Bob Cousy\", \"Ed Macauley\", \"Bill Sharman\"]', 'Chuck Cooper'),
(41, 'Hány szezont játszott Paul Pierce a Celtics-nél?', '[\"13\", \"15\", \"17\", \"11\"]', '15'),
(42, 'Melyik évben lett Jayson Tatum All-Star?', '[\"2019\", \"2020\", \"2021\", \"2018\"]', '2020'),
(43, 'Ki volt a Celtics kapitánya a 80-as években?', '[\"Larry Bird\", \"Kevin McHale\", \"Robert Parish\", \"Danny Ainge\"]', 'Larry Bird'),
(44, 'Hány pontot szerzett Larry Bird karrierje során?', '[\"21,791\", \"19,654\", \"23,876\", \"17,432\"]', '21,791'),
(45, 'Melyik évben nyert először MVP címet Larry Bird?', '[\"1982\", \"1984\", \"1986\", \"1980\"]', '1984'),
(46, 'Ki volt a Celtics GM-je a 2008-as bajnoki cím idején?', '[\"Danny Ainge\", \"Brad Stevens\", \"Red Auerbach\", \"Rick Pitino\"]', 'Danny Ainge'),
(47, 'Hány triplát dobott Jayson Tatum a 2022-23-as szezonban?', '[\"240\", \"229\", \"211\", \"198\"]', '229'),
(48, 'Melyik évben lett Kevin McHale All-Star?', '[\"1984\", \"1986\", \"1988\", \"1982\"]', '1984'),
(49, 'Ki volt a Celtics legjobb pontszerzője az 1985-86-os szezonban?', '[\"Larry Bird\", \"Kevin McHale\", \"Robert Parish\", \"Dennis Johnson\"]', 'Larry Bird'),
(50, 'Hány meccset játszott Bill Russell a Celtics-ben?', '[\"963\", \"875\", \"1021\", \"799\"]', '963'),
(51, 'Melyik évben draftolták Marcus Smartot?', '[\"2012\", \"2013\", \"2014\", \"2015\"]', '2014'),
(52, 'Ki nyerte a 2022-es Keleti döntő MVP címét?', '[\"Jayson Tatum\", \"Jaylen Brown\", \"Marcus Smart\", \"Al Horford\"]', 'Jayson Tatum'),
(53, 'Hány bajnoki döntőt játszott a Celtics a Lakers ellen?', '[\"12\", \"10\", \"8\", \"14\"]', '12'),
(54, 'Melyik évben vonult vissza Bill Russell?', '[\"1967\", \"1969\", \"1971\", \"1965\"]', '1969'),
(55, 'Ki volt a Celtics első edzője?', '[\"John Russell\", \"Red Auerbach\", \"Honey Russell\", \"Doc Rivers\"]', 'Honey Russell');

-- --------------------------------------------------------

--
-- Tábla szerkezet ehhez a táblához `rooms`
--

CREATE TABLE `rooms` (
  `id` int(11) NOT NULL,
  `name` varchar(100) NOT NULL,
  `description` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_hungarian_ci;

--
-- A tábla adatainak kiíratása `rooms`
--

INSERT INTO `rooms` (`id`, `name`, `description`) VALUES
(1, 'Celtics Rajongók', 'Beszélgessünk a csapatról és a meccsekről!'),
(2, 'Mérkőzés Elemzések', 'Elemezzük a legutóbbi meccseket.');

-- --------------------------------------------------------

--
-- Tábla szerkezet ehhez a táblához `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `username` varchar(50) NOT NULL,
  `email` varchar(100) NOT NULL,
  `password` varchar(255) NOT NULL,
  `role` varchar(20) DEFAULT NULL,
  `token` varchar(255) DEFAULT NULL,
  `profile_pic` varchar(255) DEFAULT NULL,
  `is_banned` tinyint(1) DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_hungarian_ci;

--
-- A tábla adatainak kiíratása `users`
--

INSERT INTO `users` (`id`, `username`, `email`, `password`, `role`, `token`, `profile_pic`, `is_banned`) VALUES
(1, 'név', 'nev@gmail.com', '$2y$10$POSZeYgi.p0GJjTqKm5hEeaZK8OJrBbEXB.3xgRgBAziu0/dOSJ0G', 'admin', NULL, NULL, 0),
(2, 'lacika', 'lacika@gmail.cpm', '$2y$10$aAFQcHbEpUIYPtoiqK/aNu62kMSTkKFHKZDejPEhd2QdQsfZy.b4u', NULL, NULL, NULL, 0),
(3, 'asd', 'asd@gmail.com', '$2y$10$gc1idcnan3NMvK48UddKLuaCTGeeaeZxCVFUMe.aqOaAR.6gfjwr.', NULL, NULL, NULL, 0),
(4, 'macsari475', 'laszlomacsari475@gmail.com', '$2y$10$ttbAm3HPLrdAbdz88RXAQu9C3OdpH8cNlU8vJIf1dGp82LcxuC1Gq', NULL, NULL, NULL, 0),
(5, 'maci', 'maci@gmail.com', '$2y$10$nDKTBMClmfHGTaA4ZpY27.G6kAl6ggTJPnmcNnwu81E6mVAwFdYZ2', NULL, NULL, NULL, 0);

--
-- Indexek a kiírt táblákhoz
--

--
-- A tábla indexei `messages`
--
ALTER TABLE `messages`
  ADD PRIMARY KEY (`id`),
  ADD KEY `room_id` (`room_id`),
  ADD KEY `user_id` (`user_id`);

--
-- A tábla indexei `players`
--
ALTER TABLE `players`
  ADD PRIMARY KEY (`id`);

--
-- A tábla indexei `quiz_questions`
--
ALTER TABLE `quiz_questions`
  ADD PRIMARY KEY (`id`);

--
-- A tábla indexei `rooms`
--
ALTER TABLE `rooms`
  ADD PRIMARY KEY (`id`);

--
-- A tábla indexei `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`);

--
-- A kiírt táblák AUTO_INCREMENT értéke
--

--
-- AUTO_INCREMENT a táblához `messages`
--
ALTER TABLE `messages`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=12;

--
-- AUTO_INCREMENT a táblához `players`
--
ALTER TABLE `players`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=93;

--
-- AUTO_INCREMENT a táblához `quiz_questions`
--
ALTER TABLE `quiz_questions`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=56;

--
-- AUTO_INCREMENT a táblához `rooms`
--
ALTER TABLE `rooms`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- AUTO_INCREMENT a táblához `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=6;

--
-- Megkötések a kiírt táblákhoz
--

--
-- Megkötések a táblához `messages`
--
ALTER TABLE `messages`
  ADD CONSTRAINT `messages_ibfk_1` FOREIGN KEY (`room_id`) REFERENCES `rooms` (`id`),
  ADD CONSTRAINT `messages_ibfk_2` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
