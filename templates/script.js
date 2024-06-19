
function togglePasswordVisibility() {
    var x = document.getElementById("password");
    if (x.type === "password") {
        x.type = "text";
    } else {
        x.type = "password";
    }
}

// Fonction appelée lors de la soumission du formulaire
document.querySelector('form').addEventListener('submit', function(e) {
    e.preventDefault(); // Empêche le rechargement de la page

    var email = document.querySelector('input[type="email"]').value;
    var password = document.querySelector('input[type="password"]').value;
    var redirectUrl = document.body.getAttribute('data-redirect-url');
    var rememberMe = document.querySelector('input[type="checkbox"]').checked;

    if (email !== "admin@gmail.com") {
        alert('L\'email est incorrect.');
    } else if (password !== "admin") {
        alert('Le mot de passe est incorrect.');
    } else if (password !== "admin",email !== "admin@gmail.com" ) {
        alert('Données incorrectes.');
    } else {
        if (rememberMe) {
            localStorage.setItem('email', email);
            localStorage.setItem('password', password);
        } else {
            localStorage.removeItem('email');
            localStorage.removeItem('password');
        }
        window.location.href = redirectUrl; // Assurez-vous que 'accueil.html' est bien dans le même dossier ou ajustez le chemin si nécessaire
    }
});


// Affiche les données sauvegardées si 'remember me' était coché
window.onload = function() {
    var savedEmail = localStorage.getItem('email');
    var savedPassword = localStorage.getItem('password');
    if (savedEmail && savedPassword) {
        document.querySelector('input[type="email"]').value = savedEmail;
        document.querySelector('input[type="password"]').value = savedPassword;
        document.querySelector('input[type="checkbox"]').checked = true;
    }
};
