// ==========================================
// AI Threat Detection Loader
// ==========================================

window.addEventListener("load", function () {

    const loader = document.getElementById("loader");

    if (!loader) return;

    // Small delay for smooth animation
    setTimeout(function () {

        loader.style.opacity = "0";
        loader.style.visibility = "hidden";

        setTimeout(function () {

            loader.style.display = "none";

        }, 500);

    }, 700);

});

// ==========================================
// Page Transition Loader (Optional)
// ==========================================

document.querySelectorAll("a").forEach(link => {

    link.addEventListener("click", function (e) {

        const href = this.getAttribute("href");

        // Ignore external links, anchors, and logout
        if (
            !href ||
            href.startsWith("#") ||
            href.startsWith("javascript:") ||
            this.target === "_blank" ||
            href.includes("logout")
        ) {
            return;
        }

        const loader = document.getElementById("loader");

        if (loader) {

            loader.style.display = "flex";
            loader.style.opacity = "1";
            loader.style.visibility = "visible";

        }

    });

});