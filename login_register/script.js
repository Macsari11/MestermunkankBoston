function showForm(formId) {
    document.querySelectorAll('.form-box').forEach(form => {
        form.classList.remove('active');
    });
    document.getElementById(formId).classList.add('active');
}

document.addEventListener("DOMContentLoaded", () => {
    const forms = document.querySelectorAll('.form-box');

    
    window.showForm = (formId) => {
        forms.forEach(form => {
            form.classList.toggle('active', form.id === formId);
            form.classList.remove('visible'); 
        });
        handleScroll(); 
    };

    
    const handleScroll = () => {
        forms.forEach(form => {
            const inView = form.getBoundingClientRect().top < window.innerHeight * 0.8;
            form.classList.toggle('visible', form.classList.contains('active') && inView);
        });
    };

    window.addEventListener("scroll", handleScroll);
    handleScroll(); 
});