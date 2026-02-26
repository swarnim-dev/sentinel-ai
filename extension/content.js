// Listen for messages from background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "show_warning") {
        injectWarningBanner(request);
    }
});

function injectWarningBanner(data) {
    // Remove any existing banner first
    const existing = document.getElementById("sentinel-warning-banner");
    if (existing) existing.remove();

    const riskPercent = Math.round((data.riskScore || 0.5) * 100);
    const riskLevel = riskPercent >= 70 ? "high" : riskPercent >= 40 ? "medium" : "low";
    const riskLabel = riskPercent >= 70 ? "HIGH RISK" : riskPercent >= 40 ? "MEDIUM" : "LOW";

    // Build reasons HTML
    let reasonsHtml = "";
    if (data.explanations && data.explanations.length > 0) {
        reasonsHtml = `<ul class="sentinel-reasons-list">` +
            data.explanations.map(e => `<li>${escapeHtml(e)}</li>`).join("") +
            `</ul>`;
    } else {
        reasonsHtml = `<ul class="sentinel-reasons-list">
            <li>The overall URL pattern matches known phishing websites in our database.</li>
        </ul>`;
    }

    const banner = document.createElement("div");
    banner.id = "sentinel-warning-banner";

    banner.innerHTML = `
        <div class="sentinel-banner-header">
            <strong>🛡️ Sentinel AI — Phishing Warning</strong>
            <button id="sentinel-close-btn" title="Dismiss">&times;</button>
        </div>
        <div class="sentinel-banner-body">
            <div class="sentinel-risk-gauge">
                <div class="sentinel-risk-circle sentinel-risk-${riskLevel}">
                    ${riskPercent}%
                </div>
                <div class="sentinel-risk-label">${riskLabel}</div>
            </div>
            <div class="sentinel-details">
                <h3>Why This Page Was Flagged</h3>
                <p class="sentinel-subtitle">
                    Our AI model detected features commonly associated with phishing.
                    Review the reasons below before proceeding.
                </p>
                ${reasonsHtml}
                <div class="sentinel-feedback">
                    <span>Was this helpful?</span>
                    <button id="sentinel-btn-phishing">✓ Yes, it's Phishing</button>
                    <button id="sentinel-btn-safe">✗ No, it's Safe</button>
                </div>
            </div>
        </div>
    `;

    document.body.prepend(banner);

    // Push page content down so it isn't hidden behind the fixed banner
    document.body.style.marginTop = banner.offsetHeight + "px";

    // Event Listeners
    document.getElementById("sentinel-close-btn").addEventListener("click", () => {
        banner.remove();
        document.body.style.marginTop = "";
    });

    document.getElementById("sentinel-btn-phishing").addEventListener("click", () => {
        sendFeedback(data.type, "phishing");
        showThanks(banner, "Thanks! Your feedback helps protect other students. 🎓");
    });

    document.getElementById("sentinel-btn-safe").addEventListener("click", () => {
        sendFeedback(data.type, "safe");
        showThanks(banner, "Thanks! We'll refine our model with your input. 📚");
    });
}

function showThanks(banner, message) {
    banner.innerHTML = `<div class="sentinel-thankyou">${message}</div>`;
    setTimeout(() => {
        banner.remove();
        document.body.style.marginTop = "";
    }, 2500);
}

function escapeHtml(text) {
    const div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
}

function sendFeedback(type, userLabel) {
    fetch("http://127.0.0.1:8000/feedback", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            item_type: type || "url",
            url: window.location.href,
            user_label: userLabel,
            prediction_was: "phishing"
        })
    }).catch(e => console.error("Feedback failed", e));
}

// ── Gmail email scanning (basic) ──
setInterval(() => {
    let emailBody = document.querySelector('.a3s.aiL');
    if (emailBody && !emailBody.dataset.scanned) {
        emailBody.dataset.scanned = "true";
        chrome.runtime.sendMessage({
            action: "scan_email_text",
            content: emailBody.innerText
        }, (response) => {
            if (response && response.prediction === "phishing") {
                injectWarningBanner({
                    type: "email",
                    riskScore: response.risk_score,
                    explanations: response.explanations
                });
            }
        });
    }
}, 3000);
