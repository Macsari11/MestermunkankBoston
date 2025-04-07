document.addEventListener("DOMContentLoaded", function () {
    const chatMessages = document.getElementById("chat-messages");
    const messageInput = document.getElementById("message-input");

    // Üzenet küldése
    function sendMessage() {
        const messageText = messageInput.value.trim();
        if (messageText) {
            const currentTime = new Date();
            const message = {
                user: username, // A username globálisan definiált a PHP-ból
                text: messageText,
                time: currentTime.toLocaleTimeString('hu-HU', { 
                    hour: '2-digit', 
                    minute: '2-digit', 
                    second: '2-digit' 
                })
            };
            addMessage(message, true);
            messageInput.value = "";
            scrollToBottom();
        }
    }

    // Üzenet megjelenítése
    function addMessage(message, isMyMessage = false) {
        const messageElement = document.createElement("div");
        messageElement.classList.add("chat-message");
        messageElement.classList.add(isMyMessage ? "my-message" : "other-message");

        // Felhasználónév és idő hozzáadása
        const userTime = document.createElement("div");
        userTime.innerHTML = `<strong>${message.user}</strong> <span class="message-time">${message.time}</span>`;
        
        const contentSpan = document.createElement("span");
        contentSpan.classList.add("message-content");
        contentSpan.textContent = message.text;

        messageElement.appendChild(userTime);
        messageElement.appendChild(contentSpan);

        chatMessages.appendChild(messageElement);
        messageElement.scrollIntoView({ behavior: "smooth" });
    }

    // Enter billentyű támogatás
    messageInput.addEventListener("keypress", function (e) {
        if (e.key === "Enter") {
            sendMessage();
        }
    });

    // Chat ablak aljára görgetés
    function scrollToBottom() {
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }

    // Példaüzenetek betöltése
    const exampleMessages = [
        { 
            user: "CelticsFan", 
            text: "Szia, hogy vagy?", 
            time: new Date().toLocaleTimeString('hu-HU', { 
                hour: '2-digit', 
                minute: '2-digit', 
                second: '2-digit' 
            }) 
        },
        { 
            user: "GreenTeam", 
            text: "Jól vagyok, köszi!", 
            time: new Date().toLocaleTimeString('hu-HU', { 
                hour: '2-digit', 
                minute: '2-digit', 
                second: '2-digit' 
            }) 
        }
    ];
    exampleMessages.forEach(msg => addMessage(msg, false));

    // Küldés gomb eseménykezelő
    const sendButton = document.querySelector(".chat-send-btn");
    if (sendButton) {
        sendButton.addEventListener("click", sendMessage);
    } else {
        console.error('Nem található .chat-send-btn elem a DOM-ban');
    }

    // "Lépj be a chatbe!" gomb görgetése
    const heroButton = document.querySelector(".hero-button");
    const chatSection = document.querySelector(".chat-section");
    if (heroButton && chatSection) {
        heroButton.addEventListener("click", function () {
            chatSection.scrollIntoView({ behavior: "smooth" });
        });
    } else {
        console.error('Nem található .hero-button vagy .chat-section elem a DOM-ban');
    }

    // Zárt linkek kezelése
    document.querySelectorAll('.nav-links a.locked').forEach(link => {
        if (!link.dataset.lockedInitialized) {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                alert('Kérjük, jelentkezz be a tartalom eléréséhez!');
            });
            link.dataset.lockedInitialized = 'true';
        }
    });

    // Dinamikus évszám a footerben
    const yearElement = document.getElementById('year');
    if (yearElement) {
        yearElement.textContent = new Date().getFullYear();
    } else {
        console.error('Nem található #year elem a DOM-ban');
    }
});