// ==========================================
// Profile Module
// ==========================================

document.addEventListener("DOMContentLoaded", function () {

    console.log("Profile Module Loaded");

    animateCards();

});

// ==========================================
// Card Animation
// ==========================================

function animateCards() {

    const cards = document.querySelectorAll(".chart-card");

    cards.forEach((card, index) => {

        card.style.opacity = "0";

        card.style.transform = "translateY(25px)";

        setTimeout(() => {

            card.style.transition = ".5s ease";

            card.style.opacity = "1";

            card.style.transform = "translateY(0)";

        }, index * 120);

    });

}

// ==========================================
// Save Profile
// ==========================================

function saveProfile() {

    alert("✅ Profile updated successfully.");

}

// ==========================================
// Change Password
// ==========================================

function changePassword() {

    const passwordFields = document.querySelectorAll(
        "input[type='password']"
    );

    if (passwordFields.length < 3) {

        alert("Password fields not found.");

        return;

    }

    const current = passwordFields[0].value.trim();

    const password = passwordFields[1].value.trim();

    const confirm = passwordFields[2].value.trim();

    if (current === "" || password === "" || confirm === "") {

        alert("Please fill all password fields.");

        return;

    }

    if (password !== confirm) {

        alert("❌ New passwords do not match.");

        return;

    }

    alert("✅ Password changed successfully.");

    passwordFields.forEach(field => field.value = "");

}

// ==========================================
// Input Focus Effect
// ==========================================

document.querySelectorAll("input").forEach(input => {

    input.addEventListener("focus", function () {

        this.style.borderColor = "#00E5FF";

    });

    input.addEventListener("blur", function () {

        this.style.borderColor = "rgba(255,255,255,.08)";

    });

});

// ==========================================
// Button Hover Animation
// ==========================================

document.querySelectorAll(".primary-btn").forEach(button => {

    button.addEventListener("mouseenter", function () {

        this.style.transform = "translateY(-3px) scale(1.03)";

    });

    button.addEventListener("mouseleave", function () {

        this.style.transform = "translateY(0) scale(1)";

    });

});

console.log("Profile Ready");