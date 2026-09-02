const wrapper = document.querySelector(".scan-wrapper");

const steps = [
    "Initializing AI Engine",
    "Verifying Upload",
    "Extracting Features",
    "Generating MD5",
    "Generating SHA256",
    "Running XGBoost",
    "Risk Assessment",
    "Saving Database",
    "Scan Completed"
];

let progress = 0;
let current = 0;

const bar = document.getElementById("progressBar");
const status = document.getElementById("status");

function animate() {

    if (current >= steps.length) {

        setTimeout(() => {

            window.location = wrapper.dataset.next;

        }, 800);

        return;
    }

    progress += 11;

    bar.style.width = progress + "%";

    status.innerHTML = steps[current];

    document.getElementById("step" + (current + 1)).innerHTML =
        "✅ " + steps[current];

    current++;

    setTimeout(animate, 700);
}

animate();