const canvas = document.getElementById("bgCanvas");
const ctx = canvas.getContext("2d");

function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
}

resize();
window.addEventListener("resize", resize);

let particles = [];

for (let i = 0; i < 180; i++) {
    particles.push({
        x: Math.random() * canvas.width,
        y: Math.random() * canvas.height,
        size: Math.random() * 2 + 1,
        speed: Math.random() * 0.8 + 0.2
    });
}

function animate() {

    ctx.clearRect(0, 0, canvas.width, canvas.height);

    ctx.strokeStyle = "rgba(0,255,255,0.12)";
    ctx.lineWidth = 2;

    ctx.beginPath();

    for (let x = 0; x < canvas.width; x += 8) {

        let y =
            canvas.height / 2 +
            Math.sin((x * 0.01) + Date.now() * 0.001) * 50;

        if (x === 0)
            ctx.moveTo(x, y);
        else
            ctx.lineTo(x, y);
    }

    ctx.stroke();

    particles.forEach(p => {

        p.y -= p.speed;

        if (p.y < 0)
            p.y = canvas.height;

        ctx.beginPath();

        ctx.fillStyle = "#22d3ee";

        ctx.shadowBlur = 15;
        ctx.shadowColor = "#22d3ee";

        ctx.arc(
            p.x,
            p.y,
            p.size,
            0,
            Math.PI * 2
        );

        ctx.fill();
    });

    requestAnimationFrame(animate);
}

animate();