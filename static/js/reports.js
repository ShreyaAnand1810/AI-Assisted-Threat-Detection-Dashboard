// ==========================================
// Reports Module
// ==========================================

document.addEventListener("DOMContentLoaded", function () {

    console.log("Reports Module Loaded");

    animateCards();

});

// ==========================================
// Card Animation
// ==========================================

function animateCards() {

    const cards = document.querySelectorAll(".chart-card,.summary-item");

    cards.forEach((card, index) => {

        card.style.opacity = "0";
        card.style.transform = "translateY(25px)";

        setTimeout(() => {

            card.style.transition = ".5s ease";

            card.style.opacity = "1";

            card.style.transform = "translateY(0)";

        }, index * 100);

    });

}

// ==========================================
// Download PDF
// ==========================================

function downloadPDF() {

    window.location.href = "/export/pdf";

}

// ==========================================
// Download CSV
// ==========================================

function downloadCSV() {

    window.location.href = "/export/csv";

}

// ==========================================
// Print Report
// ==========================================

function printReport() {

    window.print();

}

// ==========================================
// Export Buttons Animation
// ==========================================

document.querySelectorAll(".primary-btn,.secondary-btn").forEach(btn => {

    btn.addEventListener("mouseenter", function () {

        this.style.transform = "translateY(-3px) scale(1.03)";

    });

    btn.addEventListener("mouseleave", function () {

        this.style.transform = "translateY(0) scale(1)";

    });

});

// ==========================================
// Live Date & Time
// ==========================================

const reportTime = document.getElementById("reportTime");

if (reportTime) {

    function updateTime() {

        const now = new Date();

        reportTime.innerHTML =
            now.toLocaleDateString() + " " +
            now.toLocaleTimeString();

    }

    updateTime();

    setInterval(updateTime, 1000);

}

// ==========================================
// Smooth Scroll
// ==========================================

window.scrollTo({

    top: 0,

    behavior: "smooth"

});