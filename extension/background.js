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

// ── File Download Scanner ──
const MAX_SCAN_SIZE = 10 * 1024 * 1024; // 10 MB

chrome.downloads.onChanged.addListener(async (delta) => {
    // Only act when a download finishes
    if (!delta.state || delta.state.current !== "complete") return;

    try {
        // Get download details
        const [item] = await chrome.downloads.search({ id: delta.id });
        if (!item) return;

        const filePath = item.filename;
        const fileSize = item.fileSize;
        const fileName = filePath.split("/").pop().split("\\").pop();

        // Skip files over 10MB
        if (fileSize > MAX_SCAN_SIZE) {
            console.log(`Sentinel: Skipping ${fileName} (${(fileSize / 1024 / 1024).toFixed(1)}MB > 10MB limit)`);
            return;
        }

        console.log(`Sentinel: Scanning downloaded file: ${fileName} (${(fileSize / 1024).toFixed(1)}KB)`);

        // Read the file using the file:// URL provided by Chrome
        const fileUrl = item.url;
        const response = await fetch(fileUrl);
        const blob = await response.blob();

        // Send to backend for scanning
        const formData = new FormData();
        formData.append("file", blob, fileName);

        const scanResponse = await fetch(`${API_URL}/scan/file`, {
            method: "POST",
            body: formData
        });

        const result = await scanResponse.json();

        // Log to scan history
        await logScan(
            "file://" + fileName,
            result.risk_score || 0,
            result.verdict === "safe" ? "safe" : "phishing"
        );

        // Show notification based on verdict
        if (result.verdict === "dangerous") {
            showFileNotification(
                "DANGER: Malicious File Detected",
                `${fileName} is likely dangerous!\n${result.reasons[0]}`,
                fileName
            );
        } else if (result.verdict === "suspicious") {
            showFileNotification(
                "Warning: Suspicious File",
                `${fileName} has suspicious indicators.\n${result.reasons[0]}`,
                fileName
            );
        } else {
            showFileNotification(
                "File Scan: Safe",
                `${fileName} appears clean.`,
                fileName
            );
        }

    } catch (error) {
        console.error("Sentinel: File scan error", error);
    }
});

function showFileNotification(title, message, fileName) {
    chrome.notifications.create("file-scan-" + Date.now(), {
        type: "basic",
        iconUrl: "icon.png",
        title: title,
        message: message,
        priority: 2
    });
}

