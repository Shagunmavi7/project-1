/* ==========================================================================
   MailGuard AI — Interactive Threat Scanner & Telemetry Controller
   Full support for both FastAPI backend and standalone static hosting (Netlify)
   ========================================================================== */

const PRESETS = [
  {
    label: "Safe Work Email",
    type: "ham",
    subject: "Q3 Roadmap Review Notes",
    message:
      "Hi team, thanks for joining today's sync. I uploaded the updated Q3 slides to https://docs.google.com/presentation/d/q3-roadmap. Let me know if you have feedback before Thursday's review.",
  },
  {
    label: "Friendly SMS",
    type: "ham",
    subject: "",
    message:
      "I've been searching for the right words to thank you for this breather. I promise I won't take your help for granted.",
  },
  {
    label: "Prize Spam",
    type: "spam",
    subject: "",
    message:
      "CONGRATULATIONS! You have been selected to win a FREE £1000 cash prize or latest iPhone! Text WIN to 80085 right now to claim your reward. 18+ T&C apply.",
  },
  {
    label: "PayPal Phishing",
    type: "phishing",
    subject: "Action Required: Account Temporarily Suspended",
    message:
      "URGENT: We detected unusual login activity on your PayPal account. Your account will be permanently locked within 24 hours unless you verify your identity and confirm your password at http://paypal-security-verify.xyz/login immediately.",
  },
  {
    label: "Bank IP Smishing",
    type: "phishing",
    subject: "",
    message:
      "Chase Bank Security Alert: Your debit card is temporarily locked due to unauthorized activity. Click http://192.168.45.12/verify-card to enter your PIN and restore access immediately.",
  },
  {
    label: "Parcel Shortlink",
    type: "phishing",
    subject: "USPS Delivery Failed",
    message:
      "USPS Notice: Your package is on hold due to an unpaid customs fee of $2.99. Update your billing information and confirm your address within 48 hours at http://bit.ly/usps-reconfirm-fee",
  },
];

const URL_SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
  "buff.ly", "rb.gy", "cutt.ly", "shorturl.at", "tiny.cc", "rebrand.ly"
]);

const SUSPICIOUS_TLDS = [
  ".xyz", ".top", ".club", ".work", ".click", ".link", ".tk", ".ml",
  ".ga", ".cf", ".gq", ".ru", ".cn", ".buzz", ".support", ".online", ".site", ".pw", ".icu", ".vip"
];

const OFFICIAL_BRANDS = {
  paypal: ["paypal.com"],
  amazon: ["amazon.com", "amazon.co.uk", "amazon.in", "amzn.to"],
  apple: ["apple.com", "icloud.com"],
  microsoft: ["microsoft.com", "live.com", "outlook.com", "office.com"],
  google: ["google.com", "gmail.com", "accounts.google.com"],
  netflix: ["netflix.com"],
  chase: ["chase.com"],
  citibank: ["citi.com", "citibank.com"],
  wellsfargo: ["wellsfargo.com"],
  irs: ["irs.gov"],
  dhl: ["dhl.com"],
  fedex: ["fedex.com"],
  usps: ["usps.com"],
  ups: ["ups.com"],
  instagram: ["instagram.com"],
  facebook: ["facebook.com", "fb.com"],
  whatsapp: ["whatsapp.com"]
};

const URGENCY_PATTERNS = [
  /\burgent\b/i, /\bimmediately\b/i, /\b24\s*hours?\b/i, /\b48\s*hours?\b/i,
  /\bsuspended\b/i, /\blocked\b/i, /\brestricted\b/i, /\bdeactivated\b/i,
  /\bunauthorized\b/i, /\bunusual\s+(login|activity|sign-?in)\b/i,
  /\bsecurity\s+alert\b/i, /\baction\s+required\b/i, /\bfinal\s+notice\b/i,
  /\bwill\s+be\s+(closed|terminated|locked|suspended)\b/i,
  /\bcompromised\b/i, /\bexpir(e|es|ing|ed)\b/i, /\baccount\s+on\s+hold\b/i
];

const CREDENTIAL_PATTERNS = [
  /\bverify\s+your\b/i, /\bconfirm\s+your\b/i, /\bupdate\s+your\b/i,
  /\bvalidate\s+your\b/i, /\bpassword\b/i, /\botp\b/i, /\bpin\s+code\b/i,
  /\bssn\b/i, /\bsocial\s+security\b/i, /\bcredit\s+card\b/i,
  /\bbank\s+(account|details|card)\b/i, /\bbilling\s+info(rmation)?\b/i,
  /\bverify\s+(identity|account|now)\b/i, /\bclick\s+(here|the\s+link|below)\b/i,
  /\blog\s*in\b/i, /\bsign\s*in\b/i, /\brestore\s+access\b/i,
  /\benter\s+your\s+(pin|code|details)\b/i
];

const FINANCIAL_PATTERNS = [
  /\bwire\s+transfer\b/i, /\binvoice\b/i, /\brefund\b/i, /\btax\b/i,
  /\bpayment\s+(failed|declined|overdue|pending)\b/i,
  /\baccount\s+(number|balance)\b/i, /\bclaim\s+your\b/i,
  /\bprize\b/i, /\bwallet\b/i, /\bcrypto\b/i, /\bcustoms\s+fee\b/i
];

const SPAM_PATTERNS = [
  /\b(congratulations|selected\s+to\s+win|winner|free\s+entry|cash\s+prize|claim\s+your\s+reward|text\s+[a-z0-9]+\s+to\s+\d{4,6}|ringtone|discount|opt\s*out|100%\s+free)\b/i
];

const URL_REGEX = /(?:https?:\/\/|www\.)[^\s<>"'\)\]]+/gi;

const HISTORY_KEY = "mailguard_scan_history_v1";
const GAUGE_CIRCUMFERENCE = 2 * Math.PI * 50; // r=50 -> 314.159

let batchData = [];
let currentBatchFilter = "ALL";
let metricsLoaded = false;
let isCloudBackend = false;

// ---- DOM Helpers ----
const $ = (id) => document.getElementById(id);

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function showToast(msg) {
  const el = $("toast");
  el.textContent = msg;
  el.classList.remove("hidden");
  clearTimeout(showToast._timer);
  showToast._timer = setTimeout(() => el.classList.add("hidden"), 3200);
}

// ---- Navigation Tabs ----
document.querySelectorAll(".nav-tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    const target = btn.dataset.tab;
    document.querySelectorAll(".nav-tab").forEach((b) => {
      b.classList.toggle("active", b === btn);
      b.setAttribute("aria-selected", b === btn ? "true" : "false");
    });
    document.querySelectorAll(".tab-panel").forEach((p) => {
      p.classList.toggle("active", p.id === `tab-${target}`);
    });
    if (target === "intelligence" && !metricsLoaded) {
      loadMetrics();
    }
  });
});

// ---- Health Check ----
async function checkHealth() {
  try {
    const res = await fetch("/api/health");
    if (res.ok) {
      const data = await res.json();
      if (data.status === "ok") {
        isCloudBackend = true;
        const accPct = data.accuracy ? `${(data.accuracy * 100).toFixed(1)}% Acc` : "Active";
        $("modelStatusText").textContent = `3-Class Ensemble • ${accPct}`;
        return;
      }
    }
  } catch {}
  isCloudBackend = false;
  $("modelStatusText").textContent = "Threat Engine • Active (Netlify)";
}

// ---- Presets ----
function renderPresets() {
  const wrap = $("presetChips");
  wrap.innerHTML = PRESETS.map(
    (p, idx) => `
      <button type="button" class="preset-chip" data-preset="${idx}">
        <span class="chip-dot ${p.type}"></span>
        ${escapeHtml(p.label)}
      </button>
    `
  ).join("");

  wrap.querySelectorAll(".preset-chip").forEach((chip) => {
    chip.addEventListener("click", () => {
      const p = PRESETS[Number(chip.dataset.preset)];
      $("subjectInput").value = p.subject;
      $("messageInput").value = p.message;
      updateComposerStats();
      runAnalysis();
    });
  });
}

// ---- Composer Counters ----
function updateComposerStats() {
  const text = $("messageInput").value;
  const trimmed = text.trim();
  $("charCount").textContent = text.length;
  $("wordCount").textContent = trimmed ? trimmed.split(/\s+/).length : 0;
  const urls = text.match(URL_REGEX) || [];
  $("urlCount").textContent = urls.length;
}

$("messageInput").addEventListener("input", updateComposerStats);
$("messageInput").addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
    e.preventDefault();
    runAnalysis();
  }
});

$("clearBtn").addEventListener("click", () => {
  $("subjectInput").value = "";
  $("messageInput").value = "";
  updateComposerStats();
  $("resultsStack").classList.add("hidden");
  $("emptyResultState").classList.remove("hidden");
  $("messageInput").focus();
});

$("analyzeBtn").addEventListener("click", runAnalysis);

// ---- Client-Side Phishing & Spam Analyzer (Netlify / Static Fallback) ----
function runClientSideAnalysis(message, subject) {
  let fullText = message.trim();
  if (subject && subject.trim()) {
    fullText = `Subject: ${subject.trim()}\n\n${fullText}`;
  }

  const lower = fullText.toLowerCase();
  const redFlags = [];
  const inspectedUrls = [];
  const highlights = [];
  let riskScore = 0;

  let hasIpUrl = false;
  let hasShortener = false;
  let hasSuspiciousTld = false;
  let hasAtInUrl = false;
  let hasBrandImpersonation = false;
  let hasInsecureHttp = false;

  const urlMatches = Array.from(fullText.matchAll(/(?:https?:\/\/|www\.)[^\s<>"'\)\]]+/gi));
  const domains = [];

  for (const m of urlMatches) {
    const rawUrl = m[0].replace(/[.,;:!?]+$/, "");
    const start = m.index;
    const end = start + rawUrl.length;

    let host = "";
    let proto = "http";
    try {
      const parsed = new URL(rawUrl.startsWith("http") ? rawUrl : "http://" + rawUrl);
      host = parsed.hostname.toLowerCase();
      proto = parsed.protocol.replace(":", "").toLowerCase();
    } catch {
      host = rawUrl.replace(/^https?:\/\//i, "").split("/")[0].toLowerCase();
    }

    const urlFlags = [];
    if (host) domains.push(host);
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)) {
      hasIpUrl = true;
      urlFlags.push("Raw IP Address");
    }
    if (URL_SHORTENERS.has(host) || Array.from(URL_SHORTENERS).some(s => host.endsWith("." + s))) {
      hasShortener = true;
      urlFlags.push("URL Shortener");
    }
    if (SUSPICIOUS_TLDS.some(tld => host.endsWith(tld))) {
      hasSuspiciousTld = true;
      urlFlags.push("High-Risk TLD");
    }
    if (rawUrl.includes("@")) {
      hasAtInUrl = true;
      urlFlags.push("Redirect Obfuscation (@)");
    }
    if (rawUrl.toLowerCase().startsWith("http://")) {
      hasInsecureHttp = true;
      urlFlags.push("Unencrypted HTTP");
    }

    inspectedUrls.push({
      raw: rawUrl,
      host: host || "unknown",
      protocol: proto,
      flags: urlFlags,
      suspicious: urlFlags.length > 0
    });

    highlights.push({
      start,
      end,
      text: rawUrl,
      category: urlFlags.length > 0 ? "url_danger" : "url_info"
    });
  }

  // Brand Impersonation Check
  const impersonatedBrands = [];
  if (domains.length > 0) {
    for (const [brand, officialList] of Object.entries(OFFICIAL_BRANDS)) {
      const brandRegex = new RegExp(`\\b${brand}\\b`, "i");
      if (brandRegex.test(lower)) {
        for (const item of inspectedUrls) {
          const host = item.host;
          if (host !== "unknown" && !officialList.some(off => host === off || host.endsWith("." + off))) {
            hasBrandImpersonation = true;
            impersonatedBrands.push(`${brand.charAt(0).toUpperCase() + brand.slice(1)} -> ${host}`);
            if (!item.flags.includes(`Impersonates ${brand}`)) {
              item.flags.push(`Impersonates ${brand}`);
              item.suspicious = true;
            }
          }
        }
      }
    }
  }

  function collectMatches(patterns, category) {
    let hits = 0;
    const terms = [];
    for (const pat of patterns) {
      const match = fullText.match(pat);
      if (match) {
        hits++;
        terms.push(match[0]);
        const mAll = Array.from(fullText.matchAll(new RegExp(pat.source, "gi")));
        for (const m of mAll) {
          highlights.push({
            start: m.index,
            end: m.index + m[0].length,
            text: m[0],
            category
          });
        }
      }
    }
    return { hits, terms };
  }

  const urgency = collectMatches(URGENCY_PATTERNS, "urgency");
  const credentials = collectMatches(CREDENTIAL_PATTERNS, "credential");
  const financial = collectMatches(FINANCIAL_PATTERNS, "financial");
  const spamMatches = collectMatches(SPAM_PATTERNS, "financial");

  if (hasIpUrl) {
    riskScore += 40;
    redFlags.push({
      severity: "critical",
      category: "URL",
      title: "Raw IP Address Link",
      detail: "Link points directly to a numeric IP address instead of a verified domain name."
    });
  }
  if (hasBrandImpersonation) {
    riskScore += 40;
    redFlags.push({
      severity: "critical",
      category: "Impersonation",
      title: "Possible Brand Impersonation",
      detail: `Message references a known brand but links to an unofficial domain (${impersonatedBrands.slice(0, 3).join(", ")}).`
    });
  }
  if (hasSuspiciousTld) {
    riskScore += 25;
    redFlags.push({
      severity: "high",
      category: "URL",
      title: "High-Risk Domain Extension",
      detail: "Embedded URL uses a top-level domain frequently abused in phishing campaigns."
    });
  }
  if (hasAtInUrl) {
    riskScore += 30;
    redFlags.push({
      severity: "high",
      category: "URL",
      title: "URL Obfuscation (@ Symbol)",
      detail: "Contains an '@' inside the URL, often used to disguise the real destination host."
    });
  }
  if (hasShortener) {
    riskScore += 20;
    redFlags.push({
      severity: "medium",
      category: "URL",
      title: "Shortened URL Detected",
      detail: "Uses a link shortener that hides the true destination website."
    });
  }
  if (hasInsecureHttp && (credentials.hits > 0 || urgency.hits > 0)) {
    riskScore += 15;
    redFlags.push({
      severity: "medium",
      category: "Transport",
      title: "Unencrypted HTTP Link with Sensitive Request",
      detail: "Plain HTTP link paired with account security or login language."
    });
  }
  if (credentials.hits > 0) {
    riskScore += Math.min(30, credentials.hits * 15);
    redFlags.push({
      severity: "high",
      category: "Credentials",
      title: "Credential or Verification Harvesting",
      detail: `Detected ${credentials.hits} sensitive prompt(s): ${credentials.terms.slice(0, 4).join(", ")}.`
    });
  }
  if (urgency.hits > 0) {
    riskScore += Math.min(25, urgency.hits * 12);
    redFlags.push({
      severity: "medium",
      category: "Social Engineering",
      title: "Urgency / Account Lockout Pressure",
      detail: `Detected ${urgency.hits} pressure cue(s): ${urgency.terms.slice(0, 4).join(", ")}.`
    });
  }
  if (financial.hits > 0 && (urlMatches.length > 0 || urgency.hits > 0 || credentials.hits > 0)) {
    riskScore += Math.min(15, financial.hits * 8);
    redFlags.push({
      severity: "medium",
      category: "Financial",
      title: "Financial or Payment Lure",
      detail: `Detected ${financial.hits} financial cue(s): ${financial.terms.slice(0, 4).join(", ")}.`
    });
  }

  riskScore = Math.min(100, riskScore);

  // Classify
  let finalLabel = "HAM";
  let probMap = { ham: 0.95, spam: 0.03, phishing: 0.02 };

  if (riskScore >= 45 || hasBrandImpersonation || hasIpUrl || (hasSuspiciousTld && credentials.hits > 0)) {
    finalLabel = "PHISHING";
    const phishProb = Math.min(0.998, 0.85 + (riskScore / 100) * 0.14);
    probMap = {
      ham: Number(((1 - phishProb) * 0.7).toFixed(4)),
      spam: Number(((1 - phishProb) * 0.3).toFixed(4)),
      phishing: Number(phishProb.toFixed(4))
    };
  } else if (spamMatches.hits > 0 || (/(\b(win|prize|claim|free|call\s*\d+|text\s+[a-z0-9]+)\b)/i.test(lower) && !hasBrandImpersonation)) {
    finalLabel = "SPAM";
    probMap = { ham: 0.015, spam: 0.978, phishing: 0.007 };
  } else if (riskScore >= 25) {
    finalLabel = "HAM";
    probMap = { ham: 0.78, spam: 0.04, phishing: 0.18 };
  } else {
    finalLabel = "HAM";
    probMap = { ham: 0.982, spam: 0.011, phishing: 0.007 };
  }

  let threatScore = 0;
  if (finalLabel === "PHISHING") {
    threatScore = Math.max(72, Math.min(100, Math.round(riskScore * 0.9 + probMap.phishing * 20)));
  } else if (finalLabel === "SPAM") {
    threatScore = 65;
  } else {
    threatScore = Math.min(24, Math.round(riskScore * 0.4));
  }

  let riskLevel = "SAFE";
  let verdictSummary = "";
  let recommendedAction = "";

  if (finalLabel === "PHISHING") {
    riskLevel = threatScore >= 90 ? "CRITICAL" : "HIGH";
    verdictSummary = "High-confidence phishing indicators detected. This message attempts to steal credentials or impersonate a trusted service.";
    recommendedAction = "Do NOT click any links, enter credentials, or reply. Report as phishing.";
  } else if (finalLabel === "SPAM") {
    riskLevel = "MEDIUM";
    verdictSummary = "Unsolicited promotional or bulk spam pattern detected based on promotional cues and text structure.";
    recommendedAction = "Avoid replying or texting back shortcodes. Mark as spam and delete.";
  } else {
    riskLevel = riskScore >= 20 ? "LOW" : "SAFE";
    verdictSummary = "No spam or phishing threat patterns detected. Message structure and language look legitimate.";
    recommendedAction = "Safe to read and respond normally.";
  }

  // Deduplicate highlight spans
  highlights.sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));
  const mergedHl = [];
  let lastEnd = -1;
  for (const h of highlights) {
    if (h.start >= lastEnd) {
      mergedHl.push(h);
      lastEnd = h.end;
    }
  }

  return {
    prediction: finalLabel,
    ml_prediction: finalLabel,
    escalated_by_signals: finalLabel === "PHISHING" && riskScore >= 50,
    confidence: probMap[finalLabel.toLowerCase()],
    probabilities: probMap,
    threat_score: threatScore,
    phishing_risk_score: riskScore,
    risk_level: riskLevel,
    verdict_summary: verdictSummary,
    recommended_action: recommendedAction,
    red_flags: redFlags,
    urls: inspectedUrls,
    highlights: mergedHl,
    analyzed_text: fullText,
    stats: {
      length: fullText.length,
      word_count: fullText.trim() ? fullText.trim().split(/\s+/).length : 0,
      url_count: urlMatches.length
    }
  };
}

// ---- Live Single Analysis ----
async function runAnalysis() {
  const message = $("messageInput").value.trim();
  const subject = $("subjectInput").value.trim();
  if (!message) {
    showToast("Please paste a message or select a sample preset first.");
    $("messageInput").focus();
    return;
  }

  setAnalyzing(true);
  try {
    let data = null;
    try {
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message, subject }),
      });
      if (res.ok) {
        data = await res.json();
      }
    } catch {}

    if (!data) {
      // Use Client-Side Threat Engine (works on Netlify without Python server)
      data = runClientSideAnalysis(message, subject);
    }

    renderAnalysisResult(data);
    saveToHistory(subject, message, data);
  } catch (err) {
    showToast(`Error: ${err.message}`);
  } finally {
    setAnalyzing(false);
  }
}

function setAnalyzing(loading) {
  $("analyzeBtn").disabled = loading;
  $("analyzeSpinner").classList.toggle("hidden", !loading);
  $("analyzeIcon").classList.toggle("hidden", loading);
  $("analyzeBtnText").textContent = loading ? "Scanning..." : "Scan Message";
}

function renderAnalysisResult(data) {
  $("emptyResultState").classList.add("hidden");
  $("resultsStack").classList.remove("hidden");

  const pred = data.prediction; // HAM | SPAM | PHISHING
  const verdictCard = $("verdictCard");
  verdictCard.className = `card verdict-card state-${pred}`;

  // Gauge animation
  const score = Number(data.threat_score || 0);
  const offset = GAUGE_CIRCUMFERENCE * (1 - score / 100);
  const arc = $("gaugeArc");
  arc.style.stroke =
    pred === "PHISHING" ? "#f43f5e" : pred === "SPAM" ? "#f59e0b" : "#10b981";
  requestAnimationFrame(() => {
    arc.style.strokeDashoffset = offset;
  });
  $("threatScoreValue").textContent = score;

  const pill = $("verdictPill");
  pill.className = `verdict-pill ${pred}`;
  pill.textContent =
    pred === "HAM"
      ? "SAFE / HAM"
      : pred === "SPAM"
      ? "SPAM DETECTED"
      : "PHISHING THREAT";

  $("riskLevelPill").textContent = `RISK: ${data.risk_level}`;
  $("escalatedPill").classList.toggle("hidden", !data.escalated_by_signals);
  $("verdictSummary").textContent = data.verdict_summary;
  $("recommendedAction").textContent = data.recommended_action;

  // Probabilities
  const p = data.probabilities || {};
  const hamPct = ((p.ham || 0) * 100).toFixed(1);
  const spamPct = ((p.spam || 0) * 100).toFixed(1);
  const phishPct = ((p.phishing || 0) * 100).toFixed(1);

  $("probHamText").textContent = `${hamPct}%`;
  $("probSpamText").textContent = `${spamPct}%`;
  $("probPhishText").textContent = `${phishPct}%`;
  $("probHamBar").style.width = `${hamPct}%`;
  $("probSpamBar").style.width = `${spamPct}%`;
  $("probPhishBar").style.width = `${phishPct}%`;
  $("signalScoreBadge").textContent = `Phishing Signals: ${data.phishing_risk_score}/100`;

  // Highlighted Message
  $("highlightedMessage").innerHTML = buildHighlightedHtml(
    data.analyzed_text || "",
    data.highlights || []
  );

  // URL Forensics
  const urls = data.urls || [];
  const urlCard = $("urlForensicsCard");
  if (urls.length > 0) {
    urlCard.classList.remove("hidden");
    $("urlForensicsCount").textContent = `${urls.length} link${urls.length > 1 ? "s" : ""}`;
    $("urlList").innerHTML = urls
      .map(
        (u) => `
      <div class="url-item ${u.suspicious ? "suspicious" : ""}">
        <div class="url-raw">${escapeHtml(u.raw)}</div>
        <div class="url-meta">
          <span>Host: <strong>${escapeHtml(u.host)}</strong></span>
          <span>•</span>
          <span>Protocol: <strong>${escapeHtml(u.protocol.toUpperCase())}</strong></span>
          ${
            u.flags.length
              ? u.flags.map((f) => `<span class="url-tag">${escapeHtml(f)}</span>`).join("")
              : `<span class="url-tag clean">No URL anomalies</span>`
          }
        </div>
      </div>`
      )
      .join("");
  } else {
    urlCard.classList.add("hidden");
  }

  // Red Flags
  const flags = data.red_flags || [];
  $("redFlagsCount").textContent = `${flags.length} flag${flags.length === 1 ? "" : "s"}`;
  if (flags.length === 0) {
    $("redFlagsList").innerHTML = `
      <div class="clean-flag-banner">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
        <span>No phishing URLs, brand impersonation, or credential-harvesting patterns detected.</span>
      </div>`;
  } else {
    $("redFlagsList").innerHTML = flags
      .map(
        (f) => `
      <div class="flag-item">
        <span class="sev-badge ${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</span>
        <div>
          <div class="flag-title">${escapeHtml(f.title)}</div>
          <div class="flag-detail">${escapeHtml(f.detail)}</div>
        </div>
      </div>`
      )
      .join("");
  }
}

function buildHighlightedHtml(text, highlights) {
  if (!highlights.length) return escapeHtml(text);
  let out = "";
  let cursor = 0;
  for (const h of highlights) {
    if (h.start > cursor) {
      out += escapeHtml(text.slice(cursor, h.start));
    }
    const seg = text.slice(h.start, h.end);
    out += `<span class="hl-tok ${escapeHtml(h.category)}" title="${escapeHtml(h.category)}">${escapeHtml(seg)}</span>`;
    cursor = h.end;
  }
  if (cursor < text.length) {
    out += escapeHtml(text.slice(cursor));
  }
  return out;
}

// ---- Scan History ----
function loadHistory() {
  try {
    return JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
  } catch {
    return [];
  }
}

function saveToHistory(subject, message, result) {
  const list = loadHistory();
  list.unshift({
    subject,
    message,
    prediction: result.prediction,
    threat_score: result.threat_score,
    ts: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
  });
  localStorage.setItem(HISTORY_KEY, JSON.stringify(list.slice(0, 12)));
  renderHistory();
}

function renderHistory() {
  const list = loadHistory();
  const el = $("historyList");
  if (!list.length) {
    el.innerHTML = `<div class="empty-mini">No scans yet. Select a sample above or paste a message to begin.</div>`;
    return;
  }
  el.innerHTML = list
    .map(
      (item, idx) => `
      <div class="history-item" data-hidx="${idx}">
        <span class="mini-badge ${item.prediction}">${item.prediction}</span>
        <span class="history-preview">${escapeHtml(item.subject ? `${item.subject} — ${item.message}` : item.message)}</span>
        <span class="mono" style="font-size:11px;color:var(--text-muted)">${item.threat_score}/100</span>
      </div>`
    )
    .join("");

  el.querySelectorAll(".history-item").forEach((row) => {
    row.addEventListener("click", () => {
      const item = list[Number(row.dataset.hidx)];
      $("subjectInput").value = item.subject || "";
      $("messageInput").value = item.message || "";
      updateComposerStats();
      runAnalysis();
    });
  });
}

$("clearHistoryBtn").addEventListener("click", () => {
  localStorage.removeItem(HISTORY_KEY);
  renderHistory();
});

// ---- Batch & CSV Scanner ----
document.querySelectorAll("#batchModeSwitch .seg-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll("#batchModeSwitch .seg-btn").forEach((b) => b.classList.toggle("active", b === btn));
    const mode = btn.dataset.mode;
    $("batchTextPane").classList.toggle("hidden", mode !== "text");
    $("batchCsvPane").classList.toggle("hidden", mode !== "csv");
  });
});

$("loadBatchSampleBtn").addEventListener("click", () => {
  $("batchTextarea").value = PRESETS.map((p) => p.message).join("\n");
});

$("runBatchBtn").addEventListener("click", async () => {
  const lines = $("batchTextarea")
    .value.split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);
  if (!lines.length) {
    showToast("Paste at least one message line to scan.");
    return;
  }
  $("runBatchBtn").disabled = true;
  $("runBatchBtn").textContent = "Scanning...";

  try {
    let data = null;
    try {
      const res = await fetch("/api/analyze-batch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ messages: lines }),
      });
      if (res.ok) data = await res.json();
    } catch {}

    if (!data) {
      // Client-side batch fallback for Netlify
      const items = [];
      const counts = { HAM: 0, SPAM: 0, PHISHING: 0 };
      lines.forEach((msg, idx) => {
        const res = runClientSideAnalysis(msg, "");
        counts[res.prediction] = (counts[res.prediction] || 0) + 1;
        items.push({
          index: idx + 1,
          preview: msg.slice(0, 140) + (msg.length > 140 ? "..." : ""),
          message: msg,
          prediction: res.prediction,
          risk_level: res.risk_level,
          threat_score: res.threat_score,
          phishing_risk_score: res.phishing_risk_score,
          probabilities: res.probabilities,
          red_flag_count: res.red_flags.length,
          top_flag: res.red_flags.length ? res.red_flags[0].title : "None",
        });
      });
      data = { total: items.length, summary: counts, results: items };
    }

    displayBatchResults(data);
    showToast(`Scanned ${data.total} messages.`);
  } catch (err) {
    showToast(`Error: ${err.message}`);
  } finally {
    $("runBatchBtn").disabled = false;
    $("runBatchBtn").textContent = "Run Batch Scan";
  }
});

// CSV Dropzone
const dropzone = $("csvDropzone");
const csvInput = $("csvFileInput");

dropzone.addEventListener("dragover", (e) => {
  e.preventDefault();
  dropzone.classList.add("dragover");
});
dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragover"));
dropzone.addEventListener("drop", (e) => {
  e.preventDefault();
  dropzone.classList.remove("dragover");
  if (e.dataTransfer.files.length) uploadCsvFile(e.dataTransfer.files[0]);
});
csvInput.addEventListener("change", () => {
  if (csvInput.files.length) uploadCsvFile(csvInput.files[0]);
});

async function uploadCsvFile(file) {
  showToast(`Uploading & scanning ${file.name}...`);
  try {
    let data = null;
    try {
      const form = new FormData();
      form.append("file", file);
      const res = await fetch("/api/analyze-csv", { method: "POST", body: form });
      if (res.ok) data = await res.json();
    } catch {}

    if (!data) {
      // In-browser CSV parse fallback for Netlify
      const text = await file.text();
      const lines = text.split(/\r?\n/).filter(l => l.trim().length > 0);
      if (lines.length <= 1) throw new Error("CSV file is empty or has no data.");

      const header = lines[0].split(",").map(c => c.trim().replace(/^["']|["']$/g, ""));
      let msgColIdx = -1;
      for (let i = 0; i < header.length; i++) {
        const col = header[i].toLowerCase();
        if (col.includes("message") || col.includes("text") || col.includes("body") || col.includes("content")) {
          msgColIdx = i;
          break;
        }
      }
      if (msgColIdx === -1) msgColIdx = header.length - 1;

      const items = [];
      const counts = { HAM: 0, SPAM: 0, PHISHING: 0 };
      for (let i = 1; i < lines.length && items.length < 200; i++) {
        const row = lines[i];
        let msg = row;
        // Simple column split if multiple columns
        if (row.includes(",")) {
          const parts = row.split(",");
          msg = parts[msgColIdx] || parts[parts.length - 1] || row;
        }
        msg = msg.replace(/^["']|["']$/g, "").trim();
        if (!msg) continue;

        const res = runClientSideAnalysis(msg, "");
        counts[res.prediction] = (counts[res.prediction] || 0) + 1;
        items.push({
          index: items.length + 1,
          preview: msg.slice(0, 140) + (msg.length > 140 ? "..." : ""),
          message: msg,
          prediction: res.prediction,
          risk_level: res.risk_level,
          threat_score: res.threat_score,
          phishing_risk_score: res.phishing_risk_score,
          probabilities: res.probabilities,
          red_flag_count: res.red_flags.length,
          top_flag: res.red_flags.length ? res.red_flags[0].title : "None",
        });
      }
      data = {
        filename: file.name,
        detected_column: header[msgColIdx] || "Message",
        total: items.length,
        summary: counts,
        results: items
      };
    }

    displayBatchResults(data);
    showToast(`Scanned ${data.total} rows from ${file.name}.`);
  } catch (err) {
    showToast(`Error: ${err.message}`);
  } finally {
    csvInput.value = "";
  }
}

function displayBatchResults(data) {
  batchData = data.results || [];
  $("batchResultsWrap").classList.remove("hidden");
  $("kpiTotal").textContent = data.total || 0;
  $("kpiHam").textContent = data.summary?.HAM || 0;
  $("kpiSpam").textContent = data.summary?.SPAM || 0;
  $("kpiPhish").textContent = data.summary?.PHISHING || 0;
  renderBatchTable();
}

document.querySelectorAll("#batchFilters .filter-pill").forEach((pill) => {
  pill.addEventListener("click", () => {
    document.querySelectorAll("#batchFilters .filter-pill").forEach((p) => p.classList.toggle("active", p === pill));
    currentBatchFilter = pill.dataset.filter;
    renderBatchTable();
  });
});

function renderBatchTable() {
  const rows =
    currentBatchFilter === "ALL"
      ? batchData
      : batchData.filter((r) => r.prediction === currentBatchFilter);

  const tbody = $("batchTableBody");
  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:24px;color:var(--text-muted)">No messages match this filter.</td></tr>`;
    return;
  }

  tbody.innerHTML = rows
    .map(
      (r) => `
      <tr>
        <td class="mono">${r.index}</td>
        <td><span class="mini-badge ${r.prediction}">${r.prediction}</span></td>
        <td class="mono">${r.threat_score}/100</td>
        <td class="preview-cell" title="${escapeHtml(r.message)}">${escapeHtml(r.preview)}</td>
        <td>${escapeHtml(r.top_flag)}</td>
        <td><button class="text-btn inspect-row-btn" data-idx="${r.index}">Inspect →</button></td>
      </tr>`
    )
    .join("");

  tbody.querySelectorAll(".inspect-row-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const item = batchData.find((x) => x.index === Number(btn.dataset.idx));
      if (!item) return;
      $("subjectInput").value = "";
      $("messageInput").value = item.message;
      updateComposerStats();
      document.querySelector('.nav-tab[data-tab="scanner"]').click();
      runAnalysis();
    });
  });
}

$("exportCsvBtn").addEventListener("click", () => {
  if (!batchData.length) return;
  const header = ["Index", "Prediction", "RiskLevel", "ThreatScore", "HamProb", "SpamProb", "PhishingProb", "TopFlag", "Message"];
  const lines = [header.join(",")];
  for (const r of batchData) {
    const row = [
      r.index,
      r.prediction,
      r.risk_level,
      r.threat_score,
      r.probabilities.ham,
      r.probabilities.spam,
      r.probabilities.phishing,
      `"${String(r.top_flag).replace(/"/g, '""')}"`,
      `"${String(r.message).replace(/"/g, '""')}"`,
    ];
    lines.push(row.join(","));
  }
  const blob = new Blob([lines.join("\n")], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "mailguard_scan_results.csv";
  a.click();
  URL.revokeObjectURL(url);
});

// ---- Model Intelligence Tab ----
async function loadMetrics() {
  try {
    let res = await fetch("/api/metrics");
    if (!res.ok) res = await fetch("/static/metrics.json");
    if (!res.ok) res = await fetch("/metrics.json");

    if (res.ok) {
      const m = await res.json();
      metricsLoaded = true;
      renderMetrics(m);
      return;
    }
  } catch (err) {
    try {
      const res = await fetch("/static/metrics.json");
      if (res.ok) {
        const m = await res.json();
        metricsLoaded = true;
        renderMetrics(m);
        return;
      }
    } catch {}
    showToast("Could not load model telemetry.");
  }
}

function renderMetrics(m) {
  const bin = m.binary_benchmark;
  const tc = m.three_class;
  const baseline = bin.models.find((x) => x.model.includes("Original")) || bin.models[0];
  const upgraded = bin.models.find((x) => x.model.includes("Ensemble")) || bin.models[bin.models.length - 1];

  const accGain = ((upgraded.accuracy - baseline.accuracy) * 100).toFixed(2);
  const recGain = ((upgraded.recall - baseline.recall) * 100).toFixed(2);

  $("heroStats").innerHTML = `
    <div class="hero-stat">
      <div class="hero-stat-val">${(tc.accuracy * 100).toFixed(2)}%</div>
      <div class="hero-stat-lbl">3-Class Accuracy</div>
      <div class="hero-stat-delta">Macro F1: ${(tc.macro_f1 * 100).toFixed(2)}%</div>
    </div>
    <div class="hero-stat">
      <div class="hero-stat-val">${(upgraded.accuracy * 100).toFixed(2)}%</div>
      <div class="hero-stat-lbl">Spam/Ham Accuracy</div>
      <div class="hero-stat-delta">+${accGain}% vs baseline</div>
    </div>
    <div class="hero-stat">
      <div class="hero-stat-val">${(upgraded.recall * 100).toFixed(2)}%</div>
      <div class="hero-stat-lbl">Spam Recall</div>
      <div class="hero-stat-delta">+${recGain}% more spam caught</div>
    </div>
  `;

  $("cvBadge").textContent = `5-Fold CV: ${(bin.cv_5fold_accuracy_mean * 100).toFixed(2)}% Acc | ${(bin.cv_5fold_f1_mean * 100).toFixed(2)}% F1`;

  const tbody = $("binaryBenchmarkTable").querySelector("tbody");
  const sorted = [...bin.models].sort((a, b) => b.f1 - a.f1);
  tbody.innerHTML = sorted
    .map(
      (row, i) => `
      <tr class="${i === 0 ? "highlight-row" : ""}">
        <td>${escapeHtml(row.model)}</td>
        <td class="mono">${(row.accuracy * 100).toFixed(2)}%</td>
        <td class="mono">${(row.precision * 100).toFixed(2)}%</td>
        <td class="mono">${(row.recall * 100).toFixed(2)}%</td>
        <td class="mono">${(row.f1 * 100).toFixed(2)}%</td>
        <td class="mono">${row.roc_auc.toFixed(4)}</td>
      </tr>`
    )
    .join("");

  // Confusion Matrix
  $("threeClassTestCount").textContent = `${tc.test_size.toLocaleString()} test samples`;
  const labels = tc.labels_order;
  const cm = tc.confusion_matrix;
  const maxVal = Math.max(...cm.flat(), 1);
  let cmHtml = `<div class="cm-grid"><div></div>`;
  for (const lbl of labels) cmHtml += `<div class="cm-header">Pred ${lbl.toUpperCase()}</div>`;
  cm.forEach((row, i) => {
    cmHtml += `<div class="cm-row-label">True ${labels[i].toUpperCase()}</div>`;
    row.forEach((val, j) => {
      const intensity = Math.max(0.08, Math.min(0.82, val / maxVal));
      const bg =
        i === j
          ? `rgba(16, 185, 129, ${intensity})`
          : val > 0
          ? `rgba(244, 63, 94, ${Math.max(0.15, intensity)})`
          : `rgba(255, 255, 255, 0.025)`;
      cmHtml += `<div class="cm-cell" style="background:${bg}">${val}</div>`;
    });
  });
  cmHtml += `</div>`;
  $("confusionMatrixContainer").innerHTML = cmHtml;

  // Per-class cards
  $("datasetSizeBadge").textContent = `${tc.dataset_unique_rows.toLocaleString()} unique messages`;
  $("perClassGrid").innerHTML = labels
    .map((lbl) => {
      const c = tc.per_class[lbl];
      const upper = lbl.toUpperCase();
      return `
        <div class="class-metric-card">
          <div class="class-metric-head">
            <span class="mini-badge ${upper}">${upper}</span>
            <span class="mono" style="font-size:11px;color:var(--text-muted)">n=${c.support}</span>
          </div>
          <div class="metric-kv"><span>Precision</span><strong>${(c.precision * 100).toFixed(2)}%</strong></div>
          <div class="metric-kv"><span>Recall</span><strong>${(c.recall * 100).toFixed(2)}%</strong></div>
          <div class="metric-kv"><span>F1-Score</span><strong>${(c.f1 * 100).toFixed(2)}%</strong></div>
        </div>`;
    })
    .join("");

  // Architecture
  const arch = m.architecture;
  $("architectureList").innerHTML = `
    <div class="arch-group-title">Feature Engineering</div>
    ${arch.features.map((f) => `<div class="arch-item">${escapeHtml(f)}</div>`).join("")}
    <div class="arch-group-title">Soft-Voting Ensemble</div>
    ${arch.ensemble.map((e) => `<div class="arch-item">${escapeHtml(e)}</div>`).join("")}
    <div class="arch-group-title">Explainable Hybrid Guard</div>
    <div class="arch-item">${escapeHtml(arch.hybrid_guard)}</div>
  `;
}

// ---- Boot ----
renderPresets();
renderHistory();
updateComposerStats();
checkHealth();
