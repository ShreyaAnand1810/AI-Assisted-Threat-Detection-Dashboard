// ==========================================
// Security Tools
// ==========================================

// ---------- NMAP ----------

function runNmap() {

    let target = document.getElementById("target").value.trim();

    if (target === "") {
        alert("Enter IP Address");
        return;
    }

    document.getElementById("toolStatus").innerHTML = "Scanning...";

    let formData = new FormData();
    formData.append("target", target);

    fetch("/run_nmap", {
        method: "POST",
        body: formData
    })
    .then(res => res.json())
    .then(data => {

        if (data.status === "success") {

            if (data.raw_output) {
                document.getElementById("nmapResult").textContent =
                    data.raw_output;
            } else {
                document.getElementById("nmapResult").textContent =
                    JSON.stringify(data, null, 2);
            }

        } else {

            document.getElementById("nmapResult").textContent =
                data.message || "Scan failed.";

        }

        document.getElementById("toolStatus").innerHTML = "Completed";

    })
    .catch(err => {

        console.error(err);

        document.getElementById("nmapResult").textContent =
            "Unable to perform scan.";

        document.getElementById("toolStatus").innerHTML = "Failed";

    });

}


// ---------- PCAP ----------

function analyzePCAP() {

    let file = document.getElementById("pcapFile").files[0];

    if (!file) {
        alert("Choose a PCAP File");
        return;
    }

    let formData = new FormData();
    formData.append("pcap", file);

    document.getElementById("toolStatus").innerHTML = "Analyzing...";

    fetch("/read_pcap", {
        method: "POST",
        body: formData
    })
    .then(res => res.json())
    .then(data => {

        let html = `
        <div class="report-box">
            <h3>📊 PCAP Analysis Report</h3>

            <p><strong>Total Packets:</strong> ${data["Total Packets"]}</p>
            <p><strong>Threat Level:</strong> ${data["Threat Level"]}</p>

            <h4>Protocols</h4>
            <ul>
        `;

        for (const [key, value] of Object.entries(data["Protocols"])) {
            html += `<li>${key}: ${value}</li>`;
        }

        html += `
            </ul>

            <h4>Top Source IPs</h4>
            <ul>
        `;

        for (const [ip, count] of Object.entries(data["Top Source IPs"])) {
            html += `<li>${ip} (${count})</li>`;
        }

        html += `
            </ul>

            <h4>Top Destination IPs</h4>
            <ul>
        `;

        for (const [ip, count] of Object.entries(data["Top Destination IPs"])) {
            html += `<li>${ip} (${count})</li>`;
        }

        html += `
            </ul>

            <h4>Recommendations</h4>
            <ul>
        `;

        data["Recommendations"].forEach(item => {
            html += `<li>${item}</li>`;
        });

        html += `
            </ul>
        </div>
        `;

        document.getElementById("pcapResult").innerHTML = html;

        document.getElementById("toolStatus").innerHTML = "Completed";

    })
    .catch(err => {

        console.error(err);

        document.getElementById("pcapResult").textContent =
            "Analysis Failed.";

        document.getElementById("toolStatus").innerHTML = "Failed";

    });

}


// ---------- Pen Test ----------

// ---------- Pen Test ----------
// ---------- Pen Test ----------

function runPenTest() {

    document.getElementById("toolStatus").innerHTML = "Generating...";

    fetch("/penetration_report")
    .then(res => res.json())
    .then(data => {

        if (data.Error) {
            document.getElementById("penResult").innerHTML =
                `<div class="report-box"><h3>Error</h3><p>${data.Error}</p></div>`;
            document.getElementById("toolStatus").innerHTML = "Failed";
            return;
        }

        let html = `
        <div class="report-box">

            <h3>🛡️ Penetration Test Report</h3>

            <p><strong>Target:</strong> ${data.Target}</p>

            <h4>Risk Summary</h4>

            <ul>
                <li>🔴 Critical : ${data.Critical}</li>
                <li>🟠 High : ${data.High}</li>
                <li>🟡 Medium : ${data.Medium}</li>
                <li>🟢 Low : ${data.Low}</li>
            </ul>

            <h4>Open Ports</h4>

            <table style="width:100%;border-collapse:collapse;margin-top:10px;">
                <tr>
                    <th style="border:1px solid #555;padding:8px;">Port</th>
                    <th style="border:1px solid #555;padding:8px;">State</th>
                    <th style="border:1px solid #555;padding:8px;">Service</th>
                </tr>
        `;

        data["Open Ports"].forEach(port => {

            html += `
                <tr>
                    <td style="border:1px solid #555;padding:8px;">${port.Port}</td>
                    <td style="border:1px solid #555;padding:8px;">${port.State}</td>
                    <td style="border:1px solid #555;padding:8px;">${port.Service}</td>
                </tr>
            `;

        });

        html += `
            </table>

            <h4>Recommendations</h4>

            <ul>
        `;

        data.Recommendations.forEach(rec => {
            html += `<li>${rec}</li>`;
        });

        html += `
            </ul>

        </div>
        `;

        document.getElementById("penResult").innerHTML = html;

        document.getElementById("toolStatus").innerHTML = "Completed";

    })
    .catch(err => {

        console.error(err);

        document.getElementById("penResult").innerHTML =
            `<div class="report-box"><h3>Error</h3><p>Unable to generate report.</p></div>`;

        document.getElementById("toolStatus").innerHTML = "Failed";

    });

}

// ---------- Ready ----------

document.addEventListener("DOMContentLoaded", function () {

    console.log("Security Tools Ready");

});