/**
 * blocked.js — Logic for the Sentinel interstitial page.
 * Reads query params, populates the UI, and handles proceed/back buttons.
 */

const params = new URLSearchParams(window.location.search);
const blockedUrl = params.get("url") || "Unknown";
const riskScore = parseFloat(params.get("risk") || "0.5");
const riskPct = Math.round(riskScore * 100);

// Decode reasons
let reasons = [];
try {
    const raw = params.get("reasons");
    if (raw) {
        reasons = JSON.parse(decodeURIComponent(raw));
    }
} catch (e) {
    reasons = ["The URL matches patterns associated with phishing."];
}

// ── Populate UI ──
document.getElementById("blocked-url").textContent = blockedUrl;
document.getElementById("risk-pct").textContent = riskPct + "%";

const circle = document.getElementById("risk-circle");
const label = document.getElementById("risk-label");
if (riskPct >= 70) {
    circle.className = "risk-circle risk-high";
    label.textContent = "HIGH RISK";
} else {
    circle.className = "risk-circle risk-medium";
    label.textContent = "MEDIUM";
}

// ── Render reasons ──
const reasonsContainer = document.getElementById("reasons-list");
if (reasons.length > 0) {
    reasonsContainer.innerHTML = reasons.map(r =>
        `<div class="reason-card"><span class="icon">⚡</span><span>${escapeHtml(r)}</span></div>`
    ).join("");
} else {
    reasonsContainer.innerHTML =
        `<div class="reason-card"><span class="icon">⚡</span><span>The overall URL structure matches known phishing patterns in our database.</span></div>`;
}

// ── Go back ──
document.getElementById("btn-back").addEventListener("click", () => {
    if (window.history.length > 1) {
        window.history.back();
    } else {
        // If there's no history, navigate to a safe page
        window.location.href = "https://www.google.com";
    }
});

// ── Proceed (bypass) ──
document.getElementById("btn-proceed").addEventListener("click", () => {
    chrome.runtime.sendMessage(
        { action: "bypass_url", url: blockedUrl },
        () => {
            window.location.href = blockedUrl;
        }
    );
});

function escapeHtml(text) {
    const div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
}
