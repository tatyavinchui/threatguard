import os
import base64
import re
import requests
import joblib
import PyPDF2

from flask import Flask, render_template, request
from dotenv import load_dotenv

# =====================================================
# APP SETUP
# =====================================================
app = Flask(__name__)
load_dotenv()

# FIX #3: File upload size limit (5MB)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
VT_API_KEY = os.getenv("VT_API_KEY")

# =====================================================
# LOAD ML MODEL
# =====================================================
# FIX: Use BASE_DIR so it works from any directory
MODEL_PATH = os.path.join(BASE_DIR, "phishing_model.pkl")
model = joblib.load(MODEL_PATH)

# =====================================================
# HELPERS
# =====================================================
def clean_url(url: str) -> str:
    """Normalize URL for ML + heuristic analysis"""
    url = url.lower().strip()
    url = re.sub(r"https?://", "", url)
    url = re.sub(r"www\.", "", url)
    return url


def is_trusted_domain(cleaned: str, trusted_domains: list) -> bool:
    """FIX #5: Prevent bypass like 'evil-google.com' matching 'google.com'"""
    for domain in trusted_domains:
        pattern = re.compile(r'(^|\.)' + re.escape(domain) + r'(/|$)')
        if pattern.search(cleaned):
            return True
    return False


def scan_url_virustotal(url: str):
    """Check URL reputation using VirusTotal (optional)"""
    if not VT_API_KEY:
        return None

    try:
        headers = {"x-apikey": VT_API_KEY}
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        response = requests.get(api_url, headers=headers, timeout=15)
        if response.status_code != 200:
            return None

        data = response.json()
        return data["data"]["attributes"]["last_analysis_stats"]

    except Exception:
        return None


def scan_text_for_phishing(text: str):
    """Reusable phishing keyword + link scanner for email/file content"""
    text = text.lower()
    score = 0
    matched_keywords = []

    keywords = [
        "urgent", "verify", "login", "account", "password",
        "bank", "suspended", "click", "immediately", "confirm",
        "free", "bonus", "winner", "prize", "limited offer"
    ]

    for word in keywords:
        if word in text:
            score += 1
            matched_keywords.append(word)

    links = re.findall(r"https?://[^\s]+", text)

    # FIX #8: Don't blindly add +2 for ALL links — only suspicious ones
    suspicious_tlds = (".ru", ".tk", ".cn", ".xyz", ".life", ".top", ".click")
    suspicious_links = [l for l in links if any(l.endswith(t) for t in suspicious_tlds)]
    score += len(suspicious_links) * 2
    if links and not suspicious_links:
        score += 1  # Small bump for having links, not full +2

    if score >= 4:
        result = "PHISHING 🚨"
    elif score >= 2:
        result = "SUSPICIOUS ⚠️"
    else:
        result = "SAFE ✅"

    return result, score, links, matched_keywords


# =====================================================
# ROUTES
# =====================================================
@app.route("/")
def index():
    return render_template("index.html")


# ---------------- FILE SCAN ----------------
@app.route("/file-scan/", methods=["GET", "POST"])
def detect_scan():
    if request.method == "GET":
        return render_template("file_scan.html")

    if "file" not in request.files:
        return render_template("file_scan.html", message="No file uploaded")

    file = request.files["file"]

    if file.filename.endswith(".pdf"):
        reader = PyPDF2.PdfReader(file)
        text = " ".join(
            [p.extract_text() for p in reader.pages if p.extract_text()]
        )
    elif file.filename.endswith(".txt"):
        text = file.read().decode("utf-8")
    else:
        return render_template("file_scan.html", message="Only PDF or TXT allowed")

    # ---- KEYWORD SCORE ----
    keywords = [
        "urgent", "verify", "login", "account", "password",
        "bank", "suspended", "click", "immediately", "confirm",
        "free", "bonus", "winner", "congratulations", "limited"
    ]
    text_lower = text.lower()
    score = 0
    matched_keywords = []

    for word in keywords:
        if word in text_lower:
            score += 1
            matched_keywords.append(word)

    # ---- URL EXTRACT + SCAN ----
    urls_found = re.findall(r"https?://[^\s]+", text)
    url_results = []

    for url in urls_found:
        cleaned = clean_url(url)
        url_score = 0

        risk_keywords = [
            "login", "verify", "secure", "update", "confirm",
            "account", "password", "signin", "bank", "free"
        ]
        for word in risk_keywords:
            if word in cleaned:
                url_score += 1

        if cleaned.count("-") >= 2:
            url_score += 1
        if cleaned.count(".") >= 4:
            url_score += 1
        if cleaned.endswith((".ru", ".tk", ".cn", ".xyz", ".life")):
            url_score += 2

        try:
            ml_prob = model.predict_proba([cleaned])[0][1]
            if ml_prob > 0.45:
                url_score += 2
            elif ml_prob > 0.30:
                url_score += 1
        except Exception:
            pass

        if url_score >= 3:
            verdict = "PHISHING 🚨"
        elif url_score == 2:
            verdict = "SUSPICIOUS ⚠️"
        else:
            verdict = "SAFE ✅"

        url_results.append({"url": url, "verdict": verdict, "score": url_score})
        score += url_score

    # ---- FINAL VERDICT ----
    if score >= 5:
        result = "PHISHING 🚨"
    elif score >= 2:
        result = "SUSPICIOUS ⚠️"
    else:
        result = "SAFE ✅"

    return render_template(
        "file_scan.html",
        text=text[:500],  # preview only
        result=result,
        score=score,
        matched_keywords=matched_keywords,
        url_results=url_results
    )

# ---------------- URL SCAN ----------------
@app.route("/predict", methods=["POST"])
def predict():
    url = request.form.get("url", "").strip()

    # FIX #2: Validate URL format
    if not url or not url.startswith(("http://", "https://")):
        return render_template("index.html", message="Please enter a valid URL starting with http:// or https://")

    cleaned = clean_url(url)

    # ---------- TRUSTED DOMAINS ----------
    trusted_domains = [
        "google.com", "gmail.com", "youtube.com",
        "github.com", "microsoft.com", "microsoftonline.com",
        "amazon.com", "apple.com"
    ]

    # FIX #5: Use regex-based check to prevent bypass
    if is_trusted_domain(cleaned, trusted_domains):
        return render_template(
            "index.html",
            input_url=url,
            predicted_class="LEGITIMATE ✅",
            source="Trusted Domain Whitelist",
            malicious=0, suspicious=0, harmless=0, undetected=0,
            reasons=["Domain is in trusted whitelist"]
        )

    # ---------- RISK SCORE ----------
    risk_score = 0
    reasons = []

    keywords = [
        "login", "verify", "secure", "update",
        "confirm", "account", "password",
        "signin", "bank", "free", "bonus"
    ]

    for word in keywords:
        if word in cleaned:
            risk_score += 1
            reasons.append(f"Keyword detected: '{word}'")

    if cleaned.count("-") >= 2:
        risk_score += 1
        reasons.append("Too many hyphens in domain")

    if cleaned.count(".") >= 4:
        risk_score += 1
        reasons.append("Too many dots in domain")

    if cleaned.endswith((".ru", ".tk", ".cn", ".xyz", ".life")):
        risk_score += 2
        reasons.append("High-risk TLD detected")

    # ---------- ML PROBABILITY ----------
    ml_prob = model.predict_proba([cleaned])[0][1]

    if ml_prob > 0.45:
        risk_score += 2
        reasons.append(f"ML model: high phishing probability ({ml_prob:.2f})")
    elif ml_prob > 0.30:
        risk_score += 1
        reasons.append(f"ML model: moderate phishing probability ({ml_prob:.2f})")

    # ---------- FINAL DECISION ----------
    if risk_score >= 3:
        verdict = "PHISHING 🚨"
        source = f"Risk Engine (Score={risk_score})"
    elif risk_score == 2:
        verdict = "SUSPICIOUS ⚠️"
        source = f"Medium Risk (Score={risk_score})"
    else:
        verdict = "LEGITIMATE ✅"
        source = f"Low Risk (Score={risk_score})"

    # ---------- VIRUSTOTAL OVERRIDE ----------
    vt_stats = scan_url_virustotal(url)
    if vt_stats and (vt_stats["malicious"] > 0 or vt_stats["suspicious"] > 0):
        verdict = "PHISHING 🚨"
        source = "VirusTotal Intelligence"

    return render_template(
        "index.html",
        input_url=url,
        predicted_class=verdict,
        source=source,
        malicious=vt_stats["malicious"] if vt_stats else 0,
        suspicious=vt_stats["suspicious"] if vt_stats else 0,
        harmless=vt_stats["harmless"] if vt_stats else 0,
        undetected=vt_stats["undetected"] if vt_stats else 0,
        reasons=reasons
    )


# ---------------- EMAIL SCAN ----------------
@app.route("/email-scan", methods=["GET", "POST"])
def email_scan():
    result = None
    score = 0
    links = []
    matched_keywords = []

    if request.method == "POST":
        email_text = request.form.get("email_text", "")
        # FIX #8: Use shared scanner with smarter link scoring
        result, score, links, matched_keywords = scan_text_for_phishing(email_text)

    return render_template(
        "email_scan.html",
        result=result,
        score=score,
        links=links,
        matched_keywords=matched_keywords
    )


# =====================================================
# RUN
# =====================================================
if __name__ == "__main__":
    # FIX #7: Don't hardcode debug=True — read from environment
    debug_mode = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug_mode)