// ==========================================
// AI Threat Detection Dashboard
// UI Animations Only
// No Auto Refresh
// ==========================================

document.addEventListener("DOMContentLoaded", function () {

    console.log("Dashboard Loaded");

    // ======================================
    // Counter Animation
    // ======================================

    document.querySelectorAll(".counter").forEach(counter => {

        const target = Number(counter.innerText);

        if (isNaN(target)) return;

        let value = 0;

        const increment = target / 80;

        function animate() {

            value += increment;

            if (value < target) {

                counter.innerText = Math.floor(value);

                requestAnimationFrame(animate);

            } else {

                counter.innerText = target;

            }

        }

        animate();

    });

    // ======================================
    // Card Fade Animation
    // ======================================

    document.querySelectorAll(".chart-card,.stat-card,.summary-item").forEach((card, index) => {

        card.style.opacity = "0";
        card.style.transform = "translateY(25px)";

        setTimeout(() => {

            card.style.transition = ".5s ease";

            card.style.opacity = "1";

            card.style.transform = "translateY(0)";

        }, index * 80);

    });

    // ======================================
    // Progress Circle
    // ======================================

    document.querySelectorAll(".progress-circle").forEach(circle => {

        let value = circle.dataset.progress || 90;

        circle.style.background =
            `conic-gradient(#00E5FF ${value * 3.6}deg,#233957 0deg)`;

    });

    // ======================================
    // Confidence Bars
    // ======================================

    document.querySelectorAll(".confidence-fill").forEach(bar => {

        let width = bar.dataset.width || 90;

        setTimeout(() => {

            bar.style.width = width + "%";

        }, 300);

    });

    // ======================================
    // Risk Meter
    // ======================================

    document.querySelectorAll(".meter-fill").forEach(bar => {

        let risk = bar.dataset.risk || 80;

        setTimeout(() => {

            bar.style.width = risk + "%";

        }, 300);

    });

    // ======================================
    // Active Sidebar
    // ======================================

    document.querySelectorAll(".sidebar a").forEach(link => {

        if (link.href === window.location.href) {

            link.classList.add("active");

        }

    });

    // ======================================
    // 3D Hover Effect
    // ======================================

    document.querySelectorAll(".chart-card").forEach(card => {

        card.addEventListener("mousemove", function (e) {

            const rect = card.getBoundingClientRect();

            const x = e.clientX - rect.left;

            const y = e.clientY - rect.top;

            const rotateX = (y - rect.height / 2) / 30;

            const rotateY = -(x - rect.width / 2) / 30;

            card.style.transform =
                `perspective(1000px) rotateX(${rotateX}deg) rotateY(${rotateY}deg)`;

        });

        card.addEventListener("mouseleave", function () {

            card.style.transform =
                "perspective(1000px) rotateX(0deg) rotateY(0deg)";

        });

    });

    // ======================================
    // Live Clock
    // ======================================

    const clock = document.getElementById("liveClock");

    if (clock) {

        function updateClock() {

            const now = new Date();

            clock.innerHTML = now.toLocaleTimeString();

        }

        updateClock();

        setInterval(updateClock, 1000);

    }

});