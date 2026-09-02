// ==========================================
// AI Analytics
// ==========================================

document.addEventListener("DOMContentLoaded", function () {

    console.log("AI Analytics Loaded");

    animateCards();

    animateCounters();

});

// ==========================================
// Card Animation
// ==========================================

function animateCards() {

    const cards = document.querySelectorAll(".chart-card,.summary-item");

    cards.forEach((card, index) => {

        card.style.opacity = "0";
        card.style.transform = "translateY(30px)";

        setTimeout(() => {

            card.style.transition = ".6s ease";

            card.style.opacity = "1";

            card.style.transform = "translateY(0)";

        }, index * 120);

    });

}

// ==========================================
// Counter Animation
// ==========================================

function animateCounters() {

    document.querySelectorAll(".summary-item h2").forEach(counter => {

        const target = parseInt(counter.innerText);

        if (isNaN(target)) return;

        let current = 0;

        const increment = Math.max(1, target / 80);

        function update() {

            current += increment;

            if (current < target) {

                counter.innerText = Math.floor(current);

                requestAnimationFrame(update);

            }

            else {

                counter.innerText = target;

            }

        }

        update();

    });

}

// ==========================================
// Chart Hover Effect
// ==========================================

document.querySelectorAll(".chart-card").forEach(card => {

    card.addEventListener("mousemove", function (e) {

        const rect = card.getBoundingClientRect();

        const x = e.clientX - rect.left;

        const y = e.clientY - rect.top;

        const rotateX = (y - rect.height / 2) / 35;

        const rotateY = -(x - rect.width / 2) / 35;

        card.style.transform =
            `perspective(1000px)
            rotateX(${rotateX}deg)
            rotateY(${rotateY}deg)`;

    });

    card.addEventListener("mouseleave", function () {

        card.style.transform =
            "perspective(1000px) rotateX(0deg) rotateY(0deg)";

    });

});

// ==========================================
// AI Recommendation Color
// ==========================================

const aiSummary = document.querySelector(".ai-summary");

if (aiSummary) {

    aiSummary.style.animation = "fadeIn 1s ease";

}

// ==========================================
// Refresh Analytics Button (Optional)
// ==========================================

function refreshAnalytics() {

    location.reload();

}

console.log("Analytics Ready");