const searchInput = document.getElementById("searchInput");
const riskFilter = document.getElementById("riskFilter");

function filterTable() {

    const search = searchInput.value.toLowerCase();
    const risk = riskFilter.value.toLowerCase();

    const rows = document.querySelectorAll("#historyTable tbody tr");

    rows.forEach(row => {

        const filename =
            row.cells[1].innerText.toLowerCase();

        const riskValue =
            row.cells[8].innerText.toLowerCase();

        const matchName =
            filename.includes(search);

        const matchRisk =
            risk === "" ||
            riskValue === risk;

        row.style.display =
            matchName && matchRisk
            ? ""
            : "none";

    });

}

searchInput.addEventListener("keyup", filterTable);

riskFilter.addEventListener("change", filterTable);