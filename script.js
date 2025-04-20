document.addEventListener('DOMContentLoaded', () => {
    const slides = document.querySelectorAll('.carousel-slide');
    let currentSlide = 0;
    let isExploreVisible = false;

    function showSlide(index) {
        slides.forEach((slide, i) => {
            slide.classList.toggle('active', i === index);
        });
    }

    function nextSlide() {
        currentSlide = (currentSlide + 1) % slides.length;
        showSlide(currentSlide);
    }

    setInterval(nextSlide, 5000);

    showSlide(currentSlide);

    const exploreButton = document.querySelector('#explore-button');
    const exploreSection = document.querySelector('#explore-section');
    if (exploreButton && exploreSection) {
        exploreButton.addEventListener('click', () => {
            if (!isExploreVisible) {
                exploreSection.style.display = 'block';
                exploreSection.classList.add('visible');
                exploreButton.textContent = 'Elrejtés';
                window.scrollTo({
                    top: exploreSection.offsetTop,
                    behavior: 'smooth'
                });
            } else {
                exploreSection.style.display = 'none';
                exploreSection.classList.remove('visible');
                exploreButton.textContent = 'Fedezd fel!';
            }
            isExploreVisible = !isExploreVisible;
        });
    } else {
        console.error('Nem található az "explore-button" vagy "explore-section" elem');
    }

    const background = document.querySelector('.background-container');
    if (background) {
        window.addEventListener('scroll', () => {
            const scrollPosition = window.pageYOffset;
            background.style.transform = `translateY(${scrollPosition * 0.5}px)`;
        });
    } else {
        console.error('Nem található .background-container elem a DOM-ban');
    }

    document.querySelectorAll('.nav-links a.locked').forEach(link => {
        if (!link.dataset.lockedInitialized) {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                alert('Kérjük, jelentkezz be a tartalom eléréséhez!');
            });
            link.dataset.lockedInitialized = 'true';
        }
    });

    const yearElement = document.getElementById('year');
    if (yearElement) {
        yearElement.textContent = new Date().getFullYear();
    } else {
        console.error('Nem található #year elem a DOM-ban');
    }
});