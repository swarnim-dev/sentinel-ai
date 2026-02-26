document.addEventListener('DOMContentLoaded', async () => {
    const apiUrl = "http://127.0.0.1:8000";

    // Check API Health
    try {
        const res = await fetch(`${apiUrl}/docs`);
        if (res.ok) {
            document.getElementById('api-status').textContent = "Online";
            document.getElementById('api-status').style.color = "#34e89e";
        }
    } catch (e) {
        document.getElementById('api-status').textContent = "Offline";
        document.getElementById('api-status').style.color = "#ff6b6b";
    }

    // Get current tab URL and scan
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
        let currentUrl = tabs[0].url;
        document.getElementById('page-url').innerText = currentUrl;
        scanUrl(currentUrl);
    });

    document.getElementById('scan-manual-btn').addEventListener('click', () => {
        chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
            scanUrl(tabs[0].url);
        });
    });

    async function scanUrl(url) {
        if (!url.startsWith('http')) {
            document.getElementById('risk-score').textContent = "Not a scannable page";
            return;
        }

        try {
            document.getElementById('risk-score').textContent = "Scanning...";
            const response = await fetch(`${apiUrl}/predict/url`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url: url })
            });
            const data = await response.json();

            const resultBox = document.getElementById('result-box');
            const riskPct = Math.round(data.risk_score * 100);

            if (data.prediction === "phishing") {
                resultBox.className = "danger-box";
                document.getElementById('risk-score').textContent =
                    "DANGER - " + riskPct + "% risk";

                let explHtml = "";
                if (data.explanations && data.explanations.length > 0) {
                    explHtml = "<ul>";
                    data.explanations.forEach(r => { explHtml += "<li>" + r + "</li>"; });
                    explHtml += "</ul>";
                }
                document.getElementById('explanations-box').innerHTML = explHtml;
            } else {
                resultBox.className = "safe-box";
                document.getElementById('risk-score').textContent =
                    "SAFE - " + riskPct + "% risk";
                document.getElementById('explanations-box').innerHTML = "";
            }
        } catch (e) {
            document.getElementById('risk-score').textContent = "API unreachable";
        }
    }
});
