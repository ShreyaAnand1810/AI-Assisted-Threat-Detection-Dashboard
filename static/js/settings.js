// ==========================================
// Settings Module
// ==========================================

document.addEventListener("DOMContentLoaded", function () {

    console.log("Settings Loaded");

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
// Save Settings
// ==========================================

function saveSettings() {

    alert(

        "✅ Settings saved successfully."

    );

}

// ==========================================
// Theme Preview
// ==========================================

const theme = document.querySelector("select");

if (theme) {

    theme.addEventListener("change", function () {

        console.log(

            "Theme Changed :",

            this.value

        );

    });

}

// ==========================================
// Checkbox Animation
// ==========================================

document.querySelectorAll("input[type='checkbox']").forEach(box => {

    box.addEventListener("change", function () {

        if (this.checked) {

            console.log("Enabled");

        }

        else {

            console.log("Disabled");

        }

    });

});

// ==========================================
// Button Hover Effect
// ==========================================

document.querySelectorAll(".primary-btn").forEach(btn => {

    btn.addEventListener("mouseenter", function () {

        this.style.transform = "translateY(-3px) scale(1.03)";

    });

    btn.addEventListener("mouseleave", function () {

        this.style.transform = "translateY(0) scale(1)";

    });

});

console.log("Settings Ready");