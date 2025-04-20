document.addEventListener("DOMContentLoaded", function () {
    console.log("Az oldal betöltése megtörtént");

    const toggleButton = document.querySelector(".toggle-button");
    const exploreButton = document.querySelector("#explore-button");
    const exploreSection = document.querySelector("#explore-section");
    let isStartingFive = true;
    let isExploreVisible = false;

    console.log("Kezdőötös:", startingFive);
    console.log("Cserék:", benchPlayers);

    const imageBasePath = "./"; 
    const fallbackImage = "../kepek/logo.png";

    const extensionMap = {
        "Jayson Tatum": "jpg",
        "Jaylen Brown": "webp",
        "Kristaps Porzingis": "jpg",
        "Derrick White": "png",
        "Jrue Holiday": "jpg",
        "Al Horford": "jpg",
        "Payton Pritchard": "jpg",
        "Sam Hauser": "jpg",
        "Luke Kornet": "jpg",
        "Neemias Queta": "jpg",
        "Baylor Scheierman": "jpg",
        "Jaden Springer": "webp",
        "Xavier Tillman": "jpg"
    };

    function createCard(player, cardId, isBench = false) {
        const card = document.getElementById(cardId);
        if (!card) {
            console.error(`Nem található ${cardId} kártya`);
            return;
        }

        console.log(`Kártya létrehozása: ${cardId}, Játékos: ${player.name}`);
        card.classList.remove("starting", "bench", "fade-out", "fade-in");
        card.classList.add(isBench ? "bench" : "starting");

        const ribbonClass = isBench ? "bench" : "starting";
        const ribbonText = isBench ? "CSERE" : "KEZDŐÖTÖS";

        let imagePath = player.img || "";
        const playerName = player.name;
        if (extensionMap[playerName]) {
            const filename = imagePath.split("/").pop().split(".")[0];
            imagePath = `Pics/${filename}.${extensionMap[playerName]}`;
        }
        const fullImagePath = `${imageBasePath}${imagePath}`;
        console.log("Kép elérési útja:", fullImagePath);

        const safePlayer = {
            name: player.name || "Ismeretlen",
            age: player.age || "N/A",
            height: player.height || "N/A",
            position: player.position || "N/A",
            stats: player.stats || "Nincs adat",
            img: fullImagePath
        };

        const playerData = btoa(JSON.stringify(safePlayer));

        card.innerHTML = `
            <div class="holo-ribbon ${ribbonClass}">${ribbonText}</div>
            <div class="content">
                <div class="img" style="background-image: url('${fullImagePath}'); background-color: #ccc;" onerror="this.style.backgroundImage='url(${fallbackImage})';"></div>
                <div class="description">
                    <div class="title">
                        <p><strong>${safePlayer.name}</strong></p>
                    </div>
                    <div class="card-footer">
                        <span class="info-item">Kor: ${safePlayer.age}</span>
                        <span class="info-item">Magasság: ${safePlayer.height}</span>
                    </div>
                    <button class="more-info-btn" data-player='${playerData}'>Tudj meg többet</button>
                </div>
                <div class="position">${safePlayer.position}</div>
            </div>
        `;

        const moreInfoBtn = card.querySelector(".more-info-btn");
        if (moreInfoBtn) {
            moreInfoBtn.removeEventListener("click", showCardPopup);
            moreInfoBtn.addEventListener("click", showCardPopup);
            console.log(`Eseményfigyelő csatolva a ${cardId} kártyához`);
        } else {
            console.error(`Nem található .more-info-btn a ${cardId} kártyában`);
        }
    }

    function showCardPopup(event) {
        console.log("Tudj meg többet gombra kattintva");

        let player;
        try {
            const decodedData = atob(event.currentTarget.dataset.player);
            player = JSON.parse(decodedData);
            console.log("Játékos adatai:", player);
        } catch (error) {
            console.error("Hiba a JSON parseolás során:", error);
            return;
        }

        const popupOverlay = document.createElement("div");
        popupOverlay.className = "card-popup-overlay";

        const originalCard = event.currentTarget.closest(".card");
        const popupCard = originalCard.cloneNode(true);
        popupCard.className = "card card-popup";
        popupCard.style.animation = "none";

        const description = popupCard.querySelector(".description");
        description.innerHTML += `
            <p class="stats">Pozíció: ${player.position}</p>
            <p class="stats">Statisztikák: ${player.stats}</p>
            <button class="close-btn">Bezár</button>
        `;

        popupOverlay.appendChild(popupCard);
        document.body.appendChild(popupOverlay);
        document.body.style.overflow = "hidden";

        setTimeout(() => {
            popupOverlay.classList.add("visible");
        }, 10);

        function adjustPopupPosition() {
            const windowHeight = window.innerHeight;
            const popupHeight = popupCard.offsetHeight;
            const scrollTop = window.scrollY || window.pageYOffset;
            const topPosition = scrollTop + (windowHeight - popupHeight) / 2;
            popupCard.style.position = "absolute";
            popupCard.style.top = `${Math.max(topPosition, scrollTop)}px`;
            popupCard.style.left = "50%";
            popupCard.style.transform = "translateX(-50%) scale(1)";
        }

        adjustPopupPosition();
        window.addEventListener("resize", adjustPopupPosition);

        const closeBtn = popupCard.querySelector(".close-btn");
        closeBtn.addEventListener("click", () => {
            popupOverlay.classList.remove("visible");
            setTimeout(() => {
                popupOverlay.remove();
                document.body.style.overflow = "auto";
                window.removeEventListener("resize", adjustPopupPosition);
            }, 300);
        });

        popupOverlay.addEventListener("click", (e) => {
            if (e.target === popupOverlay) {
                popupOverlay.classList.remove("visible");
                setTimeout(() => {
                    popupOverlay.remove();
                    document.body.style.overflow = "auto";
                    window.removeEventListener("resize", adjustPopupPosition);
                }, 300);
            }
        });
    }

    function animateSwitch(players, isBench) {
        const cards = document.querySelectorAll(".card");
        cards.forEach((card, index) => {
            if (index < players.length) {
                card.style.display = "block";
                card.classList.add("fade-out");
                setTimeout(() => {
                    card.classList.remove("fade-out");
                    createCard(players[index], `card${index + 1}`, isBench);
                    card.classList.add("fade-in");
                    setTimeout(() => {
                        card.classList.remove("fade-in");
                    }, 500);
                }, 500);
            } else {
                card.style.display = "none";
            }
        });
    }

    exploreButton.addEventListener("click", function () {
        if (!isExploreVisible) {
            exploreSection.style.display = "block";
            exploreSection.classList.add("visible");
            exploreButton.textContent = "Elrejtés";
            window.scrollTo({
                top: exploreSection.offsetTop,
                behavior: "smooth"
            });
        } else {
            exploreSection.style.display = "none";
            exploreSection.classList.remove("visible");
            exploreButton.textContent = "Fedezd fel!";
        }
        isExploreVisible = !isExploreVisible;
    });

    console.log("Kezdőötös betöltése indul...");
    const cards = document.querySelectorAll(".card");
    cards.forEach((card, index) => {
        if (index < startingFive.length) {
            createCard(startingFive[index], `card${index + 1}`, false);
        } else {
            card.style.display = "none";
        }
    });
    document.getElementById('year').textContent = new Date().getFullYear();

    toggleButton.addEventListener("click", function () {
        const cards = document.querySelectorAll(".card");
        cards.forEach(card => card.style.display = "block");
        if (isStartingFive) {
            animateSwitch(benchPlayers, true);
            toggleButton.textContent = "Kezdőötös";
        } else {
            animateSwitch(startingFive, false);
            toggleButton.textContent = "Cserék";
        }
        isStartingFive = !isStartingFive;

        const playersSection = document.querySelector(".players-section");
        if (playersSection) {
            window.scrollTo({
                top: playersSection.offsetTop,
                behavior: "smooth"
            });
        }
    });
});