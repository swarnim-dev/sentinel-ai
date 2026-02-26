/**
 * Sentinel AI — Background Service Worker (Manifest V3)
 *
 * Intercepts navigations BEFORE the page loads.
 * If the API flags it as phishing, redirects to blocked.html interstitial.
 * Maintains a temporary bypass list so users can proceed if they choose.
 */

const API_URL = "http://127.0.0.1:8000";

// Temporary bypass set — URLs the user explicitly chose to proceed to
const bypassedUrls = new Set();

// ── Intercept navigations BEFORE the page loads ──
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    // Only intercept top-level frame
    if (details.frameId !== 0) return;

    const url = details.url;

    // Skip non-http, extension pages, and the blocked page itself
    if (!url.startsWith("http")) return;
    if (url.includes(chrome.runtime.id)) return; // Don't block our own pages

    // Skip if user already bypassed this URL
    if (bypassedUrls.has(url)) {
        bypassedUrls.delete(url); // One-time bypass
        return;
    }

    try {
        const response = await fetch(`${API_URL}/predict/url`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: url })
        });

        const data = await response.json();

        if (data.prediction === "phishing") {
            // Redirect to our blocking page with context
            const reasons = encodeURIComponent(JSON.stringify(data.explanations || []));
            const risk = data.risk_score || 0.5;
            const blockedPage = chrome.runtime.getURL(
                `blocked.html?url=${encodeURIComponent(url)}&risk=${risk}&reasons=${reasons}`
            );

            // Navigate the tab to the interstitial instead
            chrome.tabs.update(details.tabId, { url: blockedPage });
        }
    } catch (error) {
        console.error("Sentinel: API error during pre-navigation check", error);
        // If API is down, allow navigation (fail-open)
    }
});

// ── Listen for bypass requests from blocked.html ──
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "bypass_url" && request.url) {
        bypassedUrls.add(request.url);
        sendResponse({ ok: true });
        return;
    }

    // Email scanning from content script
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

        return true; // Keep channel open for async response
    }
});
