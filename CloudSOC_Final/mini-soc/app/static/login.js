const authCard = document.getElementById("authCard");

const showSignup = document.getElementById("showSignup");

const showLogin = document.getElementById("showLogin");


// =========================
// SWITCH LOGIN / SIGNUP
// =========================

showSignup.addEventListener("click", () => {

    authCard.classList.add("active");

});


showLogin.addEventListener("click", () => {

    authCard.classList.remove("active");

});


// =========================
// SHOW / HIDE PASSWORD
// =========================

const passwordButtons =
    document.querySelectorAll(".password-toggle");


passwordButtons.forEach(button => {

    button.addEventListener("click", () => {

        const targetId =
            button.getAttribute("data-target");

        const input =
            document.getElementById(targetId);

        const icon =
            button.querySelector("i");


        if (input.type === "password") {

            input.type = "text";

            icon.classList.remove("fa-eye");

            icon.classList.add("fa-eye-slash");

        } else {

            input.type = "password";

            icon.classList.remove("fa-eye-slash");

            icon.classList.add("fa-eye");

        }

    });

});


// =========================
// LOGIN
// =========================
// The login form is submitted to the server (POST /login), so nothing to intercept here.


// =========================
// SIGNUP
// =========================
// Registration is closed on this portal: show a message and send nothing.

const signupForm =
    document.getElementById("signupForm");

const signupMessage =
    document.getElementById("signupMessage");

signupForm.addEventListener("submit", function (e) {

    e.preventDefault();

    signupMessage.hidden = false;

});
