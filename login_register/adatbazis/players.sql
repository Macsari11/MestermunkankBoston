-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Gép: 127.0.0.1
-- Létrehozás ideje: 2025. Már 24. 13:05
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
(1, 'Jayson Tatum', 27, '6\'8\"', 'SF', '/images/players/JT.jpg', 'PPG: 26.9, RPG: 8.1, APG: 4.9', 1, '2025-03-24 12:02:08'),
(2, 'Jaylen Brown', 28, '6\'6\"', 'SG', '/images/players/JB.jpg', 'PPG: 23.0, RPG: 5.5, APG: 3.6', 1, '2025-03-24 12:02:08'),
(3, 'Kristaps Porzingis', 29, '7\'3\"', 'C', '/images/players/KP.jpg', 'PPG: 20.1, RPG: 7.2, BPG: 1.9', 1, '2025-03-24 12:02:08'),
(4, 'Derrick White', 30, '6\'4\"', 'PG', '/images/players/DW.jpg', 'PPG: 15.2, RPG: 4.2, APG: 5.1', 1, '2025-03-24 12:02:08'),
(5, 'Jrue Holiday', 34, '6\'4\"', 'PG', '/images/players/JH.jpg', 'PPG: 12.5, RPG: 5.4, APG: 4.8', 1, '2025-03-24 12:02:08'),
(6, 'Al Horford', 38, '6\'9\"', 'C', '/images/players/AH.jpg', 'PPG: 8.6, RPG: 6.2, APG: 2.6', 0, '2025-03-24 12:02:08'),
(7, 'Payton Pritchard', 27, '6\'1\"', 'PG', '/images/players/PP.jpg', 'PPG: 9.6, RPG: 3.2, APG: 3.4', 0, '2025-03-24 12:02:08'),
(8, 'Sam Hauser', 27, '6\'7\"', 'SF', '/images/players/SH.jpg', 'PPG: 8.9, RPG: 3.5, APG: 1.0', 0, '2025-03-24 12:02:08'),
(9, 'Luke Kornet', 29, '7\'2\"', 'C', '/images/players/LK.jpg', 'PPG: 5.3, RPG: 4.1, BPG: 1.1', 0, '2025-03-24 12:02:08'),
(10, 'Neemias Queta', 25, '7\'0\"', 'C', '/images/players/NQ.jpg', 'PPG: 4.6, RPG: 4.4, BPG: 0.8', 0, '2025-03-24 12:02:08'),
(11, 'Baylor Scheierman', 24, '6\'6\"', 'SG', '/images/players/BS.jpg', 'PPG: 3.1, RPG: 1.2, APG: 0.5', 0, '2025-03-24 12:02:08'),
(12, 'Jaden Springer', 22, '6\'4\"', 'SG', '/images/players/JS.jpg', 'PPG: 2.1, RPG: 1.0, APG: 0.8', 0, '2025-03-24 12:02:08'),
(13, 'Xavier Tillman', 26, '6\'8\"', 'PF', '/images/players/XT.jpg', 'PPG: 4.0, RPG: 2.7, APG: 1.0', 0, '2025-03-24 12:02:08');

--
-- Indexek a kiírt táblákhoz
--

--
-- A tábla indexei `players`
--
ALTER TABLE `players`
  ADD PRIMARY KEY (`id`);

--
-- A kiírt táblák AUTO_INCREMENT értéke
--

--
-- AUTO_INCREMENT a táblához `players`
--
ALTER TABLE `players`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=14;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
