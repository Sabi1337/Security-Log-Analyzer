document.addEventListener("DOMContentLoaded", function () {
    const form = document.getElementById("uploadForm");
    const alertsDiv = document.getElementById("alerts");
    const dashboard = document.getElementById("dashboard");
    const totalRequests = document.getElementById("totalRequests");
    const topIps = document.getElementById("topIps");
    const topUrls = document.getElementById("topUrls");
    const securityAlerts = document.getElementById("securityAlerts");
    let statusChart, ipChart;

    form.addEventListener("submit", function (e) {
        e.preventDefault();
        alertsDiv.innerHTML = "";
        dashboard.style.display = "none";

        const fileInput = form.querySelector("input[type=file]");
        if (!fileInput.files.length) {
            showAlert("Bitte Datei auswählen.", true);
            return;
        }

        const formData = new FormData();
        formData.append("logfile", fileInput.files[0]);

        fetch("/api/analyze", {
            method: "POST",
            body: formData,
        })
        .then(res => res.json())
        .then(data => {
            if (data.error) {
                showAlert(data.error, true);
                return;
            }
            showStats(data);
        })
        .catch(() => {
            showAlert("Server-Fehler oder keine Verbindung.", true);
        });
    });

    const exportBtn = document.getElementById("exportCsvBtn");
    if (exportBtn) {
    exportBtn.addEventListener("click", function () {
        const fileInput = form.querySelector("input[type=file]");
        if (!fileInput.files.length) {
            showAlert("Bitte Datei auswählen.", true);
            return;
        }
        const formData = new FormData();
        formData.append("logfile", fileInput.files[0]);
        fetch("/api/export", {
            method: "POST",
            body: formData,
        })
        .then(response => {
            if (!response.ok) throw new Error("Download fehlgeschlagen");
            return response.blob();
        })
        .then(blob => {
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = "log_analysis.csv";
            document.body.appendChild(a);
            a.click();
            a.remove();
            window.URL.revokeObjectURL(url);
        })
        .catch(() => {
            showAlert("Export fehlgeschlagen.", true);
        });
    });
}

    function showAlert(msg, isError) {
        alertsDiv.innerHTML = `<div class="alert${isError ? " error" : ""}">${msg}</div>`;
    }

    function showStats(stats) {
        dashboard.style.display = "block";
        totalRequests.textContent = stats.total_requests;
        topIps.textContent = stats.top_ips.map(ip => `${ip[0]} (${ip[1]})`).join(", ");
        topUrls.textContent = stats.top_urls.map(url => `${url[0]} (${url[1]})`).join(", ");

        const ctx1 = document.getElementById('statusChart').getContext('2d');
        if (statusChart) statusChart.destroy();
        statusChart = new Chart(ctx1, {
            type: 'pie',
            data: {
                labels: Object.keys(stats.status_counter),
                datasets: [{
                    data: Object.values(stats.status_counter),
                }]
            }
        });

        const ctx2 = document.getElementById('ipChart').getContext('2d');
        if (ipChart) ipChart.destroy();
        ipChart = new Chart(ctx2, {
            type: 'bar',
            data: {
                labels: stats.top_ips.map(ip => ip[0]),
                datasets: [{
                    label: 'Requests',
                    data: stats.top_ips.map(ip => ip[1]),
                }]
            },
            options: {
                plugins: { legend: { display: false } },
                indexAxis: 'y',
            }
        });

        let alerts = "";
        if (
            (stats.brute_force && stats.brute_force.length) ||
            (stats.error_ips && stats.error_ips.length) ||
            (stats.night_ips && stats.night_ips.length) ||
            (stats.traversal_attempts && stats.traversal_attempts.length) ||
            (stats.sqli_attempts && stats.sqli_attempts.length) ||
            (stats.root_logins && stats.root_logins.length)
        ) {
            if (stats.brute_force && stats.brute_force.length)
                alerts += `<div class="warn">Mögliche Brute-Force-Angriffe von: ${stats.brute_force.join(", ")}</div>`;
            if (stats.error_ips && stats.error_ips.length)
                alerts += `<div class="warn">Auffällige IPs mit vielen Fehlern: ${stats.error_ips.join(", ")}</div>`;
            if (stats.night_ips && stats.night_ips.length)
                alerts += `<div class="warn">Ungewöhnliche Zugriffszeiten (nachts) von: ${stats.night_ips.join(", ")}</div>`;
            if (stats.traversal_attempts && stats.traversal_attempts.length) {
                alerts += `<div class="warn"><b>Directory Traversal/Scanner-Angriffe erkannt:</b><br>`;
                stats.traversal_attempts.forEach(attempt => {
                    alerts += `[${attempt.datetime ? attempt.datetime : "-"}] IP: ${attempt.ip} → ${attempt.url}<br>`;
                });
                alerts += `</div>`;
            }
            if (stats.sqli_attempts && stats.sqli_attempts.length) {
                alerts += `<div class="warn"><b>SQL Injection-Versuche erkannt:</b><br>`;
                stats.sqli_attempts.forEach(attempt => {
                    alerts += `[${attempt.datetime ? attempt.datetime : "-"}] IP: ${attempt.ip} → ${attempt.url}<br>`;
                });
                alerts += `</div>`;
            }
            if (stats.root_logins && stats.root_logins.length) {
                alerts += `<div class="warn"><b>SSH-Root-Logins erkannt:</b><br>`;
                stats.root_logins.forEach(attempt => {
                    alerts += `[${attempt.datetime ? attempt.datetime : "-"}] IP: ${attempt.ip} – ${attempt.message}<br>`;
                });
                alerts += `</div>`;
            }
        } else {
            alerts = "<p>Keine Auffälligkeiten gefunden.</p>";
        }
        securityAlerts.innerHTML = alerts;
    }
});
