/**
 * Sentinel AI - Background Service Worker (Manifest V3)
 *
 * Intercepts navigations BEFORE the page loads.
 * If the API flags it as phishing, redirects to blocked.html interstitial.
 * Logs every scan to chrome.storage.local for the weekly hygiene report.
 */

const API_URL = "http://127.0.0.1:8000";

// Temporary bypass set
const bypassedUrls = new Set();

// ── Log a scan result to local storage ──
async function logScan(url, riskScore, prediction) {
    try {
        const domain = new URL(url).hostname;
        const entry = {
            domain: domain,
            risk: riskScore,
            prediction: prediction,
            timestamp: Date.now()
        };

        const result = await chrome.storage.local.get({ scanHistory: [] });
        const history = result.scanHistory;
        history.push(entry);

        // Keep only last 30 days of data to avoid bloating storage
        const thirtyDaysAgo = Date.now() - 30 * 24 * 60 * 60 * 1000;
        const trimmed = history.filter(e => e.timestamp > thirtyDaysAgo);

        await chrome.storage.local.set({ scanHistory: trimmed });
    } catch (e) {
        console.error("Sentinel: Failed to log scan", e);
    }
}

// ── Intercept navigations BEFORE the page loads ──
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    if (details.frameId !== 0) return;

    const url = details.url;

    if (!url.startsWith("http")) return;
    if (url.includes(chrome.runtime.id)) return;

    if (bypassedUrls.has(url)) {
        bypassedUrls.delete(url);
        return;
    }

    try {
        const response = await fetch(`${API_URL}/predict/url`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: url })
        });

        const data = await response.json();

        // Log every scan
        await logScan(url, data.risk_score || 0, data.prediction || "unknown");

        if (data.prediction === "phishing") {
            const reasons = encodeURIComponent(JSON.stringify(data.explanations || []));
            const risk = data.risk_score || 0.5;
            const blockedPage = chrome.runtime.getURL(
                `blocked.html?url=${encodeURIComponent(url)}&risk=${risk}&reasons=${reasons}`
            );
            chrome.tabs.update(details.tabId, { url: blockedPage });
        }
    } catch (error) {
        console.error("Sentinel: API error during pre-navigation check", error);
    }
});

// ── Listen for messages ──
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "bypass_url" && request.url) {
        bypassedUrls.add(request.url);
        sendResponse({ ok: true });
        return;
    }

    if (request.action === "open_report") {
        chrome.tabs.create({ url: chrome.runtime.getURL("report.html") });
        sendResponse({ ok: true });
        return;
    }

    if (request.action === "scan_email_text") {
        fetch(`${API_URL}/predict/email`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                body_text: request.content,
                headers: { "Subject": "Scanned Content" }
            })
        })
            .then(res => res.json())
            .then(data => sendResponse(data))
            .catch(error => {
                console.error(error);
                sendResponse({ error: "Failed to scan" });
            });

        return true;
    }
});
