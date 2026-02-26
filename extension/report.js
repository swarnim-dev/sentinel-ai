/**
 * report.js - Reads scan history from chrome.storage.local
 * and renders a 7-day Digital Hygiene Report dashboard.
 */

const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

async function loadReport() {
    const result = await chrome.storage.local.get({ scanHistory: [] });
    const history = result.scanHistory;

    // Filter to last 7 days
    const now = Date.now();
    const sevenDaysAgo = now - 7 * 24 * 60 * 60 * 1000;
    const weekData = history.filter(e => e.timestamp > sevenDaysAgo);

    // ── Stat cards ──
    const totalScans = weekData.length;
    const safeCount = weekData.filter(e => e.prediction === "safe").length;
    const phishingCount = weekData.filter(e => e.prediction === "phishing").length;
    const uniqueDomains = new Set(weekData.map(e => e.domain)).size;

    document.getElementById("total-scans").textContent = totalScans;
    document.getElementById("safe-count").textContent = safeCount;
    document.getElementById("phishing-count").textContent = phishingCount;
    document.getElementById("unique-domains").textContent = uniqueDomains;

    // ── Date range label ──
    const startDate = new Date(sevenDaysAgo);
    const endDate = new Date(now);
    document.getElementById("report-period").textContent =
        formatDate(startDate) + " - " + formatDate(endDate);

    // ── Safety score (0-100) ──
    let score = 100;
    if (totalScans > 0) {
        score = Math.round((safeCount / totalScans) * 100);
    }

    const scoreEl = document.getElementById("score-value");
    const ringEl = document.getElementById("score-ring");
    const titleEl = document.getElementById("score-title");

    scoreEl.textContent = score;

    if (score >= 90) {
        ringEl.className = "score-ring score-excellent";
        titleEl.textContent = "Excellent Hygiene!";
    } else if (score >= 70) {
        ringEl.className = "score-ring score-good";
        titleEl.textContent = "Good Hygiene";
    } else if (score >= 50) {
        ringEl.className = "score-ring score-fair";
        titleEl.textContent = "Fair - Be More Careful";
    } else {
        ringEl.className = "score-ring score-poor";
        titleEl.textContent = "Poor - High Risk Browsing";
    }

    // ── Daily bar chart ──
    renderDailyChart(weekData, now);

    // ── Top flagged domains ──
    renderDomainTable(weekData);
}

function renderDailyChart(weekData, now) {
    const chart = document.getElementById("daily-chart");
    chart.innerHTML = "";

    // Group scans by day-of-week for last 7 days
    const dailyBuckets = [];
    for (let i = 6; i >= 0; i--) {
        const dayStart = new Date(now - i * 24 * 60 * 60 * 1000);
        dayStart.setHours(0, 0, 0, 0);
        const dayEnd = new Date(dayStart);
        dayEnd.setHours(23, 59, 59, 999);

        const dayScans = weekData.filter(e => e.timestamp >= dayStart.getTime() && e.timestamp <= dayEnd.getTime());
        const safe = dayScans.filter(e => e.prediction === "safe").length;
        const phishing = dayScans.filter(e => e.prediction === "phishing").length;

        dailyBuckets.push({
            label: DAYS[dayStart.getDay()],
            safe: safe,
            phishing: phishing,
            total: safe + phishing
        });
    }

    // Find max for scaling
    const maxTotal = Math.max(1, ...dailyBuckets.map(d => d.total));

    dailyBuckets.forEach(day => {
        const col = document.createElement("div");
        col.className = "day-col";

        const bars = document.createElement("div");
        bars.className = "day-bars";

        // Phishing bar (on top)
        if (day.phishing > 0) {
            const pBar = document.createElement("div");
            pBar.className = "bar bar-phishing";
            pBar.style.height = Math.max(4, (day.phishing / maxTotal) * 100) + "px";
            pBar.title = day.phishing + " threats";
            bars.appendChild(pBar);
        }

        // Safe bar
        const sBar = document.createElement("div");
        sBar.className = "bar bar-safe";
        sBar.style.height = Math.max(2, (day.safe / maxTotal) * 100) + "px";
        sBar.title = day.safe + " safe";
        bars.appendChild(sBar);

        col.appendChild(bars);

        const label = document.createElement("div");
        label.className = "day-label";
        label.textContent = day.label;
        col.appendChild(label);

        chart.appendChild(col);
    });
}

function renderDomainTable(weekData) {
    const tbody = document.getElementById("domains-body");

    // Aggregate by domain
    const domainMap = {};
    weekData.forEach(e => {
        if (!domainMap[e.domain]) {
            domainMap[e.domain] = { count: 0, totalRisk: 0, phishing: 0 };
        }
        domainMap[e.domain].count++;
        domainMap[e.domain].totalRisk += e.risk;
        if (e.prediction === "phishing") domainMap[e.domain].phishing++;
    });

    // Sort by average risk descending
    const sorted = Object.entries(domainMap)
        .map(([domain, d]) => ({
            domain,
            count: d.count,
            avgRisk: d.totalRisk / d.count,
            phishing: d.phishing
        }))
        .sort((a, b) => b.avgRisk - a.avgRisk)
        .slice(0, 10);

    if (sorted.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="empty-state">No scans recorded yet. Browse some sites to build your report!</td></tr>';
        return;
    }

    tbody.innerHTML = sorted.map(d => {
        const riskPct = Math.round(d.avgRisk * 100);
        let badgeClass, badgeText;
        if (d.phishing > 0) {
            badgeClass = "badge-danger";
            badgeText = "Blocked";
        } else if (riskPct > 40) {
            badgeClass = "badge-warning";
            badgeText = "Suspicious";
        } else {
            badgeClass = "badge-safe";
            badgeText = "Safe";
        }

        return `<tr>
            <td>${escapeHtml(d.domain)}</td>
            <td>${d.count}</td>
            <td>${riskPct}%</td>
            <td><span class="risk-badge ${badgeClass}">${badgeText}</span></td>
        </tr>`;
    }).join("");
}

function formatDate(d) {
    const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    return months[d.getMonth()] + " " + d.getDate();
}

function escapeHtml(text) {
    const div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
}

// Run
loadReport();
